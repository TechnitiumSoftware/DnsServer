import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { Login } from './Login'
import * as client from '../api/client'
import * as statusApi from '../api/status'

afterEach(() => vi.restoreAllMocks())

describe('Login and api/status', () => {
  it('it hides the SSO button when the server says it is disabled', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: false })
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.queryByText('Sign in with SSO')).not.toBeInTheDocument())
  })

  it('it shows the SSO button when it is enabled', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: true })
    render(<Login onSuccess={() => {}} />)
    expect(await screen.findByText('Sign in with SSO')).toBeInTheDocument()
  })

  it('if status does not answer, it shows no button: SSO is not assumed', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue(null)
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.queryByText('Sign in with SSO')).not.toBeInTheDocument())
  })

  it('with factory credentials it logs itself in with admin/admin', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: true, ssoEnabled: false })
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', token: 't', displayName: 'Administrator', username: 'admin', totpEnabled: false },
    })
    const onSuccess = vi.fn()
    render(<Login onSuccess={onSuccess} />)
    await waitFor(() => expect(spy).toHaveBeenCalled())
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ user: 'admin', pass: 'admin' })
    await waitFor(() =>
      expect(onSuccess).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ forcePasswordChange: true }),
      ),
    )
  })

  it('without factory credentials it does NOT log itself in', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: false })
    const spy = vi.spyOn(client, 'apiRequest')
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.getByLabelText('Username')).toBeInTheDocument())
    expect(spy).not.toHaveBeenCalled()
  })

  it('a failed auto-login leaves no alert hanging', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: true, ssoEnabled: false })
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Invalid username or password.' })
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.getByLabelText('Username')).toBeInTheDocument())
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
