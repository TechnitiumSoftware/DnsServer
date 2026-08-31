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
  it('it requires a user with the literal text of upstream', async () => {
    render(<Login onSuccess={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByText('Please enter an username.')).toBeInTheDocument()
  })

  /*
  Upstream has these five links in a `div#footer` hanging off the `body`, so
  they show on its login screen too. Here there were none, and two of them
  —technitium.com and dnsclient.net— appeared on no other screen of the console.
  */
  it('it shows the upstream footer, which appears on its login too', async () => {
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

  it('it requires a password with the literal text of upstream', async () => {
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByText('Please enter a password.')).toBeInTheDocument()
  })

  it('it sends the user lowercased', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion)
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'ADMIN')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(llamadaLogin(spy)?.[1]?.body?.user).toBe('admin')
  })

  it('it sends includeInfo=true and by POST', async () => {
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

  it('it alerts with the server message when the credentials fail', async () => {
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

  it('it shows the OTP panel and disables the password when the server asks for 2FA', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'two-factor-required' })
    render(<Login onSuccess={() => {}} />)
    await userEvent.type(screen.getByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'secreto')
    await userEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(await screen.findByLabelText('OTP')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeDisabled()
  })

  it('with the OTP panel open and fewer than 6 digits, it alerts with the literal text', async () => {
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

  it('it hands over the session on finishing', async () => {
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

  it('it forces the password change with admin/admin and no 2FA', async () => {
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
  it('the link opens the modal, which explains the only procedure there is', async () => {
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

  it('it calls no endpoint: it is only text', async () => {
    const usuario = userEvent.setup()
    vi.spyOn(status, 'getStatus').mockResolvedValue(null as never)
    const spy = vi.spyOn(client, 'apiRequest')
    render(<Login onSuccess={() => {}} />)

    await usuario.click(screen.getByRole('button', { name: 'Forgot Password?' }))
    await screen.findByRole('dialog')
    expect(spy).not.toHaveBeenCalled()
  })
})
