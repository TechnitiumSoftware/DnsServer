import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Login } from './Login'
import * as client from '../api/client'

// shouldAdvanceTime lets the timers run with the real clock, which is what
// userEvent needs so as not to block, without losing the ability to make big
// jumps with advanceTimersByTime.
beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }))
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

async function llegarAlPanelOtp() {
  vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'two-factor-required' })
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime, delay: null })
  render(<Login onSuccess={() => {}} />)
  await user.type(screen.getByLabelText('Username'), 'admin')
  await user.type(screen.getByLabelText('Password'), 'secreto')
  await user.click(screen.getByRole('button', { name: 'Login' }))
  // With fake clocks findBy* cannot be used: it waits on timers that never
  // advance. The microtask queue is drained and the query is made synchronously.
  await act(async () => { await Promise.resolve() })
  expect(screen.getByLabelText('OTP')).toBeInTheDocument()
  return user
}

describe('panel OTP', () => {
  it('se envía solo al teclear el sexto dígito, y no antes', async () => {
    const user = await llegarAlPanelOtp()
    const spy = vi.spyOn(client, 'apiRequest')
    spy.mockClear()
    await user.type(screen.getByLabelText('OTP'), '12345')
    expect(spy).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('OTP'), '6')
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy.mock.calls[0][1]?.body?.totp).toBe('123456')
  })

  it('vuelve al login a los 30 segundos y devuelve la contraseña', async () => {
    await llegarAlPanelOtp()
    await act(async () => { vi.advanceTimersByTime(29_000) })
    expect(screen.queryByLabelText('OTP')).toBeInTheDocument()
    await act(async () => { vi.advanceTimersByTime(1_500) })
    expect(screen.queryByLabelText('OTP')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeEnabled()
  })

  it('cancela la expiración cuando el OTP se acepta', async () => {
    const user = await llegarAlPanelOtp()
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', token: 't', displayName: 'A', username: 'admin', totpEnabled: true },
    })
    await user.type(screen.getByLabelText('OTP'), '123456')
    await act(async () => { vi.advanceTimersByTime(31_000) })
    // After success the component stays mounted —the parent replaces it— so what
    // gets checked is that the timer did NOT fire: the panel is still open with
    // its value and the password is still disabled. Had the timer gone off,
    // both would have been reverted.
    expect(screen.getByLabelText('OTP')).toHaveValue('123456')
    expect(screen.getByLabelText('Password')).toBeDisabled()
  })
})
