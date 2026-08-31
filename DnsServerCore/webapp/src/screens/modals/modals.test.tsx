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
  const open = (totpEnabled = false) =>
    render(
      <ChangePassword open onOpenChange={() => {}} totpEnabled={totpEnabled} token="t" />,
    )

  it('it requires the current password, with the literal text', async () => {
    open()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter the current password.')).toBeInTheDocument()
  })

  it('it requires the new one before the confirmation: the order is contract', async () => {
    open()
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter new password.')).toBeInTheDocument()
  })

  it('it requires the confirmation', async () => {
    open()
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Please enter confirm password.')).toBeInTheDocument()
  })

  it('it warns that they do not match under the Mismatch! title', async () => {
    open()
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'otra')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Passwords do not match. Please try again.')).toBeInTheDocument()
    expect(screen.getByText('Mismatch!')).toBeInTheDocument()
  })

  it('with 2FA off it asks for no OTP', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok())
    open(false)
    expect(screen.queryByLabelText('OTP')).not.toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(spy.mock.calls[0][0]).toBe('user/changePassword')
    expect(spy.mock.calls[0][1]?.body).toEqual({ pass: 'old-one', newPass: 'nueva', totp: '' })
  })

  it('with 2FA on it requires the 6 digits', async () => {
    open(true)
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(
      await screen.findByText('Please enter the 6-digit OTP that you see in your authenticator app.'),
    ).toBeInTheDocument()
  })

  it('it confirms the change with the literal text', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok())
    open()
    await userEvent.type(screen.getByLabelText('Current Password'), 'old-one')
    await userEvent.type(screen.getByLabelText('New Password'), 'nueva')
    await userEvent.type(screen.getByLabelText('Confirm Password'), 'nueva')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Password was changed successfully.')).toBeInTheDocument()
    expect(screen.getByText('Password Changed!')).toBeInTheDocument()
  })
})

describe('Create API Token', () => {
  it('it requires the name with the literal text', async () => {
    render(<CreateApiToken open onOpenChange={() => {}} username="admin" token="t" />)
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Please enter a token name.')).toBeInTheDocument()
  })

  it('it creates the token and shows the literal message', async () => {
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
  it('it draws the QR as a data: URI, which the CSP does allow for images', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ status: 'ok', response: { totpEnabled: false, qrCodePngImage: 'iVBORw0K', secret: 'ABC' } }),
    )
    render(<Configure2FA open onOpenChange={() => {}} token="t" />)
    const img = await screen.findByAltText('QR code for the authenticator app')
    expect(img).toHaveAttribute('src', 'data:image/png;base64,iVBORw0K')
    expect(screen.getByLabelText('Secret')).toHaveValue('ABC')
  })

  it('it requires the 6 digits with the literal text', async () => {
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

  it('with 2FA already on it offers to disable it and uses the literal text', async () => {
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

  it('it lets a local user edit the name and sends it', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(perfil(false))
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByDisplayValue('Administrator')
    expect(screen.getByLabelText('User Type')).toHaveValue('Local')
    expect(screen.getByLabelText('Display Name')).toBeEnabled()
    // auth.js:678-687 — the record lists the groups and their total; it had been lost.
    expect(screen.getByLabelText('2FA Status')).toHaveValue('Disabled')
    expect(screen.getByText('Total Groups: 2')).toBeInTheDocument()
    expect(screen.getByText('Administrators')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    const call = spy.mock.calls.find((c) => c[0] === 'user/profile/set')
    expect(call?.[1]?.body).toEqual({ sessionTimeoutSeconds: '1800', displayName: 'Administrator' })
  })

  it('it disables the name for an SSO user and does NOT send it', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(perfil(true))
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByDisplayValue('Administrator')
    expect(screen.getByLabelText('User Type')).toHaveValue('Remote/SSO')
    expect(screen.getByLabelText('Display Name')).toBeDisabled()
    expect(screen.getByLabelText('2FA Status')).toHaveValue('SSO Managed')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    const call = spy.mock.calls.find((c) => c[0] === 'user/profile/set')
    expect(call?.[1]?.body).toEqual({ sessionTimeoutSeconds: '1800' })
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

  it('it lists the sessions and their total', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    expect(await screen.findByText('Total Sessions: 2')).toBeInTheDocument()
    expect(screen.getByText('10.0.1.42')).toBeInTheDocument()
    expect(screen.getByText('(current)')).toBeInTheDocument()
    // The type tag is drawn by upstream (`auth.js:703-719`) and this table had lost
    // it by being written by hand instead of with the shared cell.
    expect(screen.getByText('Standard')).toBeInTheDocument()
    expect(screen.getByText('API Token')).toBeInTheDocument()
  })

  /*
  The confirmation is the console's dialog, not the browser's native
  `confirm()`: it was the only step of the whole redesign that still opened the
  operating system's. The text is still upstream's literal (`auth.js:803`), which
  is what these two tests guard.
  */
  async function openSessionDelete() {
    await userEvent.click(screen.getByRole('button', { name: 'Actions for bbb222' }))
    await userEvent.click(screen.getByRole('button', { name: 'Delete Session' }))
  }

  it('it asks for confirmation with the literal text before deleting', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByText('Total Sessions: 2')
    await openSessionDelete()
    expect(
      screen.getByText('Are you sure you want to delete the session [bbb222] ?'),
    ).toBeInTheDocument()
  })

  it('on confirming it deletes and alerts with the literal text', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(conSesiones)
    render(<MyProfile open onOpenChange={() => {}} token="t" />)
    await screen.findByText('Total Sessions: 2')
    await openSessionDelete()
    await userEvent.click(
      screen.getByRole('button', { name: 'Delete Session', hidden: false }),
    )
    expect(spy.mock.calls.some((c) => c[0] === 'user/session/delete')).toBe(true)
    expect(await screen.findByText('The user session was deleted successfully.')).toBeInTheDocument()
    vi.unstubAllGlobals()
  })
})
