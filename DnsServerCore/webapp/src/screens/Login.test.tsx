import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Login } from './Login'
import * as client from '../api/client'
import * as status from '../api/status'

/** Finds the login call without assuming it is the first: `api/status` goes before. */
function llamadaLogin(spy: { mock: { calls: unknown[][] } }) {
  return spy.mock.calls.find((c) => c[0] === 'user/login') as
    | [string, { method?: string; body?: Record<string, string> }]
    | undefined
}

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

  /*
  Upstream has these five links in a `div#footer` hanging off the `body`, so
  they show on its login screen too. Here there were none, and two of them
  —technitium.com and dnsclient.net— appeared on no other screen of the console.
  */
  it('enseña el pie de upstream, que también sale en su login', async () => {
    render(<Login onSuccess={() => {}} />)
    for (const [nombre, destino] of [
      ['Technitium', 'https://technitium.com/'],
      ['Blog', 'https://blog.technitium.com/'],
      ['Donate', 'https://go.technitium.com/?id=35'],
      ['DNS Client at dnsclient.net', 'https://dnsclient.net/'],
      ['GitHub', 'https://github.com/TechnitiumSoftware/DnsServer'],
    ]) {
      expect(screen.getByRole('link', { name: nombre })).toHaveAttribute('href', destino)
    }
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
    expect(llamadaLogin(spy)?.[1]?.body?.user).toBe('admin')
  })

  it('envía includeInfo=true y por POST', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion)
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    const llamada = llamadaLogin(spy)
    expect(llamada).toBeDefined()
    expect(llamada?.[1]?.method).toBe('POST')
    expect(llamada?.[1]?.body?.includeInfo).toBe('true')
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

describe('Forgot Password?', () => {
  it('el enlace abre el modal, que explica el único procedimiento que existe', async () => {
    // It was missing entirely until the phase 10 inventory sweep: it was the only
    // one of upstream's 40 modals with no counterpart.
    const usuario = userEvent.setup()
    vi.spyOn(status, 'getStatus').mockResolvedValue(null as never)
    render(<Login onSuccess={() => {}} />)

    await usuario.click(screen.getByRole('button', { name: 'Forgot Password?' }))

    const dialogo = await screen.findByRole('dialog')
    expect(
      within(dialogo).getByText('To reset your password, you need to contact the DNS Server administrator.'),
    ).toBeTruthy()
    expect(within(dialogo).getByText('resetadmin.config')).toBeTruthy()
  })

  it('no llama a ningún endpoint: es sólo texto', async () => {
    const usuario = userEvent.setup()
    vi.spyOn(status, 'getStatus').mockResolvedValue(null as never)
    const spy = vi.spyOn(client, 'apiRequest')
    render(<Login onSuccess={() => {}} />)

    await usuario.click(screen.getByRole('button', { name: 'Forgot Password?' }))
    await screen.findByRole('dialog')
    expect(spy).not.toHaveBeenCalled()
  })
})
