import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Login } from './Login'
import * as client from '../api/client'

beforeEach(() => vi.restoreAllMocks())
afterEach(() => vi.restoreAllMocks())

const sesion = {
  kind: 'ok' as const,
  data: { status: 'ok', token: 't', displayName: 'Administrator', username: 'admin', totpEnabled: false },
}

describe('Login', () => {
  it('exige usuario con el texto literal de upstream', async () => {
    render(<Login onSuccess={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByText('Please enter an username.')).toBeInTheDocument()
  })

  it('exige contraseña con el texto literal de upstream', async () => {
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByText('Please enter a password.')).toBeInTheDocument()
  })

  it('envía el usuario en minúsculas', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion)
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'ADMIN')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(spy.mock.calls[0][1]?.body?.user).toBe('admin')
  })

  it('envía includeInfo=true y por POST', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion)
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(spy.mock.calls[0][0]).toBe('user/login')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(spy.mock.calls[0][1]?.body?.includeInfo).toBe('true')
  })

  it('avisa con el mensaje del servidor cuando las credenciales fallan', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'error',
      message: 'Invalid username or password for user: admin',
    })
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'mal')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(
      await screen.findByText('Invalid username or password for user: admin'),
    ).toBeInTheDocument()
  })

  it('muestra el panel OTP y deshabilita la contraseña cuando el servidor pide 2FA', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'two-factor-required' })
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByLabelText('OTP')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeDisabled()
  })

  it('con el panel OTP abierto y menos de 6 dígitos, avisa con el texto literal', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'two-factor-required' })
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    await screen.findByLabelText('OTP')
    await userEvent.type(screen.getByLabelText('OTP'), '123')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(
      await screen.findByText(
        'Please enter the 6-digit OTP that you see in your authenticator app.',
      ),
    ).toBeInTheDocument()
  })

  it('entrega la sesión al terminar', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion)
    const onSuccess = vi.fn()
    render(<Login onSuccess={onSuccess} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(onSuccess).toHaveBeenCalledWith(
      expect.objectContaining({ token: 't', displayName: 'Administrator' }),
      expect.objectContaining({ forcePasswordChange: false }),
    )
  })

  it('fuerza el cambio de contraseña con admin/admin y sin 2FA', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', token: 't', displayName: 'Administrator', username: 'admin', totpEnabled: false },
    })
    const onSuccess = vi.fn()
    render(<Login onSuccess={onSuccess} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'admin')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(onSuccess).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ forcePasswordChange: true }),
    )
  })
})
