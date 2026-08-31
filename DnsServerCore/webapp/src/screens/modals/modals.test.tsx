import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ChangePassword } from './ChangePassword'
import { CreateApiToken } from './CreateApiToken'
import { Configure2FA } from './Configure2FA'
import { MyProfile } from './MyProfile'
import * as client from '../../api/client'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown = { status: 'ok' }) => ({ kind: 'ok' as const, data })

describe('Change Password', () => {
  const abrir = (totpEnabled = false) =>
    render(
      <ChangePassword open onOpenChange={() => {}} totpEnabled={totpEnabled} token="t" />,
    )

  it('exige la contraseña actual, con el texto literal', async () => {
    abrir()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter the current password.')).toBeInTheDocument()
  })

  it('exige la nueva antes que la confirmación: el orden es contrato', async () => {
    abrir()
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter new password.')).toBeInTheDocument()
  })

  it('exige la confirmación', async () => {
    abrir()
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter confirm password.')).toBeInTheDocument()
  })

  it('avisa de que no coinciden con el título Mismatch!', async () => {
    abrir()
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'otra')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Passwords do not match. Please try again.')).toBeInTheDocument()
    expect(screen.getByText('Mismatch!')).toBeInTheDocument()
  })

  it('sin 2FA activo no pide OTP', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok())
    abrir(false)
    expect(screen.queryByLabelText('OTP')).not.toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(spy.mock.calls[0][0]).toBe('user/changePassword')
    expect(spy.mock.calls[0][1]?.body).toEqual({ pass: 'vieja', newPass: 'nueva', totp: '' })
  })

  it('con 2FA activo exige los 6 dígitos', async () => {
    abrir(true)
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(
      await screen.findByText('Please enter the 6-digit OTP that you see in your authenticator app.'),
    ).toBeInTheDocument()
  })

  it('confirma el cambio con el texto literal', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok())
    abrir()
    await userEvent.type(screen.getByLabelText('Current Password'), 'vieja')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Password was changed successfully.')).toBeInTheDocument()
    expect(screen.getByText('Password Changed!')).toBeInTheDocument()
  })
})

describe('Create API Token', () => {
  it('exige el nombre con el texto literal', async () => {
    render(<CreateApiToken open onOpenChange={() => {}} username="admin" token="t" />)
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Please enter a token name.')).toBeInTheDocument()
  })

  it('crea el token y muestra el mensaje literal', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ status: 'ok', token: 'abc' }))
    render(<CreateApiToken open onOpenChange={() => {}} username="admin" token="t" />)
    await userEvent.type(screen.getByLabelText('Token Name'), 'orbiter')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(spy.mock.calls[0][1]?.body).toEqual({ tokenName: 'orbiter' })
    expect(await screen.findByText('API token was created successfully.')).toBeInTheDocument()
    expect(screen.getByLabelText('Token')).toHaveValue('abc')
  })
})

describe('Configure 2FA', () => {
  it('pinta el QR como data: URI, que la CSP sí admite para imágenes', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ status: 'ok', response: { totpEnabled: false, qrCodePngImage: 'iVBORw0K', secret: 'ABC' } }),
    )
    render(<Configure2FA open onOpenChange={() => {}} token="t" />)
    const img = await screen.findByAltText('QR code for the authenticator app')
    expect(img).toHaveAttribute('src', 'data:image/png;base64,iVBORw0K')
    expect(screen.getByLabelText('Secret')).toHaveValue('ABC')
  })

  it('exige los 6 dígitos con el texto literal', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ status: 'ok', response: { totpEnabled: false, qrCodePngImage: 'x', secret: 'ABC' } }),
    )
    render(<Configure2FA open onOpenChange={() => {}} token="t" />)
    await screen.findByLabelText('Secret')
    await userEvent.click(screen.getByRole('button', { name: 'Enable 2FA' }))
    expect(
      await screen.findByText('Please enter the 6-digit OTP that you see in your authenticator app.'),
    ).toBeInTheDocument()
  })

  it('con 2FA ya activo ofrece desactivarlo y usa el texto literal', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ status: 'ok', response: { totpEnabled: true, qrCodePngImage: '', secret: '' } }),
    )
    render(<Configure2FA open onOpenChange={() => {}} token="t" />)
    const btn = await screen.findByRole('button', { name: 'Disable 2FA' })
    await userEvent.click(btn)
    expect(
      await screen.findByText('Two-factor authentication (2FA) was disabled successfully.'),
    ).toBeInTheDocument()
  })
})

describe('My Profile', () => {
  const perfil = (isSsoUser: boolean) =>
    ok({
      status: 'ok',
      response: {
        displayName: 'Administrator',
        username: 'admin',
        isSsoUser,
        totpEnabled: false,
        memberOfGroups: ['Everyone', 'Administrators'],
        sessionTimeoutSeconds: 1800,
      },
    })

  it('a un usuario local le deja editar el nombre y lo manda', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(perfil(false))
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByDisplayValue('Administrator')
    expect(screen.getByLabelText('User Type')).toHaveValue('Local')
    expect(screen.getByLabelText('Display Name')).toBeEnabled()
    // auth.js:678-687 — la ficha lista los grupos y su total; se había perdido.
    expect(screen.getByLabelText('2FA Status')).toHaveValue('Disabled')
    expect(screen.getByText('Total Groups: 2')).toBeInTheDocument()
    expect(screen.getByText('Administrators')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    const llamada = spy.mock.calls.find((c) => c[0] === 'user/profile/set')
    expect(llamada?.[1]?.body).toEqual({ sessionTimeoutSeconds: '1800', displayName: 'Administrator' })
  })

  it('a un usuario de SSO le deshabilita el nombre y NO lo manda', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(perfil(true))
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByDisplayValue('Administrator')
    expect(screen.getByLabelText('User Type')).toHaveValue('Remote/SSO')
    expect(screen.getByLabelText('Display Name')).toBeDisabled()
    expect(screen.getByLabelText('2FA Status')).toHaveValue('SSO Managed')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    const llamada = spy.mock.calls.find((c) => c[0] === 'user/profile/set')
    expect(llamada?.[1]?.body).toEqual({ sessionTimeoutSeconds: '1800' })
  })
})

describe('My Profile — sesiones activas', () => {
  const conSesiones = ok({
    status: 'ok',
    response: {
      displayName: 'Administrator',
      username: 'admin',
      isSsoUser: false,
      totpEnabled: true,
      memberOfGroups: ['Everyone'],
      sessionTimeoutSeconds: 1800,
      sessions: [
        { username: 'admin', isCurrentSession: true, partialToken: 'aaa111', type: 'Standard', tokenName: null, lastSeen: '2026-08-25T14:33:26Z', lastSeenRemoteAddress: '10.0.1.42', lastSeenUserAgent: 'Chrome' },
        { username: 'admin', isCurrentSession: false, partialToken: 'bbb222', type: 'ApiToken', tokenName: 'orbiter', lastSeen: '2026-08-24T09:00:00Z', lastSeenRemoteAddress: '10.0.70.11', lastSeenUserAgent: 'curl' },
      ],
    },
  })

  it('lista las sesiones y su total', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    expect(await screen.findByText('Total Sessions: 2')).toBeInTheDocument()
    expect(screen.getByText('10.0.1.42')).toBeInTheDocument()
    expect(screen.getByText('(current)')).toBeInTheDocument()
    // La etiqueta de tipo la pinta upstream (`auth.js:703-719`) y esta tabla la
    // había perdido al escribirse a mano en vez de con la celda compartida.
    expect(screen.getByText('Standard')).toBeInTheDocument()
    expect(screen.getByText('API Token')).toBeInTheDocument()
  })

  it('pide confirmación con el texto literal antes de borrar', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    const confirmar = vi.fn().mockReturnValue(false)
    vi.stubGlobal('confirm', confirmar)
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByText('Total Sessions: 2')
    await userEvent.click(screen.getByLabelText('Delete session bbb222'))
    expect(confirmar).toHaveBeenCalledWith('Are you sure you want to delete the session [bbb222] ?')
    vi.unstubAllGlobals()
  })

  it('si se confirma, borra y avisa con el texto literal', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByText('Total Sessions: 2')
    await userEvent.click(screen.getByLabelText('Delete session bbb222'))
    expect(spy.mock.calls.some((c) => c[0] === 'user/session/delete')).toBe(true)
    expect(await screen.findByText('The user session was deleted successfully.')).toBeInTheDocument()
    vi.unstubAllGlobals()
  })
})
