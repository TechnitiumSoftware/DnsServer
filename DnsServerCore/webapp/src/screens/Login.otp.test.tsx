import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Login } from './Login'
import * as client from '../api/client'

// shouldAdvanceTime deja que los temporizadores corran con el reloj real, que
// es lo que necesita userEvent para no bloquearse, sin perder la capacidad de
// dar saltos grandes con advanceTimersByTime.
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
  // Con relojes falsos no se puede usar findBy*: espera con temporizadores que
  // nunca avanzan. Se vacía la cola de microtareas y se consulta en síncrono.
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
    // Tras el éxito el componente sigue montado —lo sustituye el padre—, así que
    // lo que se comprueba es que el temporizador NO disparó: el panel sigue
    // abierto con su valor y la contraseña sigue deshabilitada. Si el
    // temporizador hubiera saltado, ambas cosas se habrían revertido.
    expect(screen.getByLabelText('OTP')).toHaveValue('123456')
    expect(screen.getByLabelText('Password')).toBeDisabled()
  })
})
