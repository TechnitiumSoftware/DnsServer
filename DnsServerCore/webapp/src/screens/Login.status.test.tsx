import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { Login } from './Login'
import * as client from '../api/client'
import * as statusApi from '../api/status'

afterEach(() => vi.restoreAllMocks())

describe('Login y api/status', () => {
  it('oculta el botón de SSO cuando el servidor dice que está deshabilitado', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: false })
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.queryByText('Sign in with SSO')).not.toBeInTheDocument())
  })

  it('muestra el botón de SSO cuando está habilitado', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: true })
    render(<Login onSuccess={() => {}} />)
    expect(await screen.findByText('Sign in with SSO')).toBeInTheDocument()
  })

  it('si status no responde, no muestra el botón: no se asume que hay SSO', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue(null)
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.queryByText('Sign in with SSO')).not.toBeInTheDocument())
  })

  it('con credenciales de fábrica entra solo con admin/admin', async () => {
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

  it('sin credenciales de fábrica NO entra solo', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: false, ssoEnabled: false })
    const spy = vi.spyOn(client, 'apiRequest')
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.getByLabelText('Username')).toBeInTheDocument())
    expect(spy).not.toHaveBeenCalled()
  })

  it('el auto-login que falla no deja una alerta colgada', async () => {
    vi.spyOn(statusApi, 'getStatus').mockResolvedValue({ hasDefaultCredentials: true, ssoEnabled: false })
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Invalid username or password.' })
    render(<Login onSuccess={() => {}} />)
    await waitFor(() => expect(screen.getByLabelText('Username')).toBeInTheDocument())
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
