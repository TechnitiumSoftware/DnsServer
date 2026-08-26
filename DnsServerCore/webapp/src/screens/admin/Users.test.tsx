import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Users } from './Users'
import * as client from '../../api/client'
import { DETALLE_USUARIO, USUARIO_ADMIN, USUARIO_NUEVO, USUARIO_SSO } from './admin.fixture'
import { elegir } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(usuarios = [USUARIO_ADMIN, USUARIO_NUEVO], detalle = DETALLE_USUARIO) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string, opts) => {
    if (path === 'admin/users/list') return ok({ response: { users: usuarios }, server: 'x' })
    if (path === 'admin/users/get') return ok({ response: detalle, server: 'x' })
    if (path === 'admin/users/set') {
      const body = (opts?.body ?? {}) as Record<string, string>
      return ok({
        response: { ...detalle, disabled: body.disabled === 'true', totpEnabled: false },
        server: 'x',
      })
    }
    if (path === 'admin/users/create') {
      return ok({ response: { ...USUARIO_NUEVO, username: 'nuevo' }, server: 'x' })
    }
    return ok({ response: {}, server: 'x' })
  })
}

const props = { token: 'tok', cluster: null, onAviso: vi.fn() }

describe('Users — la tabla', () => {
  it('pinta tipo, 2FA, estado y los dos accesos, con el total', async () => {
    servidor()
    render(<Users {...props} />)

    expect(await screen.findByText('Administrator')).toBeInTheDocument()
    expect(screen.getAllByText('Local')).toHaveLength(2)
    expect(screen.getByText('Total Users: 2')).toBeInTheDocument()
    // `0001-01-01T00:00:00` es el «nunca» de .NET: se pinta tal cual lo hace
    // upstream, con su «from 0.0.0.0» detrás.
    expect(screen.getAllByText(/from 0\.0\.0\.0$/)).toHaveLength(2)
  })

  it('un usuario de SSO sale como Remote/SSO y con el 2FA gestionado fuera', async () => {
    servidor([USUARIO_SSO])
    render(<Users {...props} />)
    expect(await screen.findByText('Remote/SSO')).toBeInTheDocument()
    expect(screen.getByText('SSO Managed')).toBeInTheDocument()
  })

  it('a un usuario de SSO no se le ofrece ni resetear la contraseña ni quitarle el 2FA', async () => {
    servidor([USUARIO_SSO])
    render(<Users {...props} />)
    await screen.findByText('Remote/SSO')
    expect(screen.queryByRole('button', { name: 'Reset Password' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Disable 2FA' })).not.toBeInTheDocument()
  })

  it('«Disable 2FA» sólo aparece si el usuario lo tiene puesto', async () => {
    servidor([{ ...USUARIO_NUEVO, totpEnabled: true }])
    render(<Users {...props} />)
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()
  })

  it('sin usuarios el total dice cero', async () => {
    servidor([])
    render(<Users {...props} />)
    expect(await screen.findByText('Total Users: 0')).toBeInTheDocument()
  })
})

describe('Users — activar y desactivar', () => {
  it('ACTIVAR no pide confirmación: sale directo', async () => {
    const spy = servidor([{ ...USUARIO_NUEVO, disabled: true }])
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'Enable' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser', disabled: 'false' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Enabled!',
      text: 'User [testuser] account was enabled successfully.',
    })
  })

  it('DESACTIVAR sí pide confirmación, con el nombre en el texto', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Disable' }))
    expect(
      screen.getByText('Are you sure you want to disable the user [testuser] account?'),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')).toBeUndefined()
  })

  it('quitar el 2FA manda `totpEnabled=false` y avisa con el literal de upstream', async () => {
    const spy = servidor([{ ...USUARIO_NUEVO, totpEnabled: true }])
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'Disable 2FA' }))
    expect(
      screen.getByText(
        'Are you sure you want to disable Two-factor authentication (2FA) for user [testuser] ?',
      ),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Disable' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser', totpEnabled: 'false' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: '2FA Disabled!',
      text: 'Two-factor authentication was disabled successfully for user [testuser].',
    })
  })

  it('borrar pide confirmación y saca la fila de la tabla', async () => {
    const spy = servidor([USUARIO_ADMIN, USUARIO_NUEVO])
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onAviso={onAviso} />)

    await user.click((await screen.findAllByRole('button', { name: 'Delete User' }))[1])
    expect(
      screen.getByText('Are you sure you want to delete the user [testuser] account?'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/delete')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser' },
    })
    expect(screen.getByText('Total Users: 1')).toBeInTheDocument()
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Deleted!',
      text: 'User account was deleted successfully.',
    })
  })
})

describe('Users — «Add User»', () => {
  async function abrir() {
    servidor()
    const user = userEvent.setup()
    render(<Users {...props} />)
    await user.click(await screen.findByRole('button', { name: 'Add User' }))
    await screen.findByLabelText('Confirm Password')
    return user
  }

  it('el orden de las cuatro validaciones es el de upstream', async () => {
    const user = await abrir()
    const anadir = screen.getByRole('button', { name: 'Add' })

    await user.click(anadir)
    expect(screen.getByText('Please enter an username to add user.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Username'), 'nuevo')
    await user.click(anadir)
    expect(screen.getByText('Please enter a password to add user.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Password'), 'uno')
    await user.click(anadir)
    expect(screen.getByText('Please enter confirm password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Confirm Password'), 'dos')
    await user.click(anadir)
    expect(screen.getByText('Passwords do not match. Please try again.')).toBeInTheDocument()
  })

  it('el nombre visible es opcional: no se valida', async () => {
    const user = await abrir()
    await user.type(screen.getByLabelText('Username'), 'nuevo')
    await user.type(screen.getByLabelText('Password'), 'x')
    await user.type(screen.getByLabelText('Confirm Password'), 'x')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    const spy = vi.mocked(client.apiRequest)
    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/create')?.[1]).toEqual({
      token: 'tok',
      method: 'POST',
      body: { displayName: '', user: 'nuevo', pass: 'x' },
    })
  })
})

describe('Users — «Reset Password»', () => {
  it('valida en orden y guarda por POST con `newPass`', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'Reset Password' }))
    const reset = screen.getByRole('button', { name: 'Reset' })

    await user.click(reset)
    expect(screen.getByText('Please enter new password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('New Password'), 'uno')
    await user.click(reset)
    expect(screen.getByText('Please enter confirm password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Confirm Password'), 'dos')
    await user.click(reset)
    expect(screen.getByText('Passwords do not match. Please try again.')).toBeInTheDocument()

    await user.clear(screen.getByLabelText('Confirm Password'))
    await user.type(screen.getByLabelText('Confirm Password'), 'uno')
    await user.click(reset)

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      method: 'POST',
      body: { user: 'testuser', newPass: 'uno' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Password Reset!',
      text: 'Password was reset successfully.',
    })
  })
})

describe('Users — el modal de detalles', () => {
  it('manda usuario, estado y tiempo de sesión, y el nombre visible si no es de SSO', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    await screen.findByLabelText('Session Timeout')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: {
        user: 'testuser',
        disabled: 'false',
        sessionTimeoutSeconds: '1800',
        displayName: 'Test User',
        memberOfGroups: '',
      },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Saved!',
      text: 'User details were saved successfully.',
    })
  })

  it('un tiempo de sesión vacío cae al 1800 por omisión, no viaja vacío', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    await user.clear(await screen.findByLabelText('Session Timeout'))
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.sessionTimeoutSeconds).toBe('1800')
  })

  it('«Add Group» añade el grupo a la lista y «None» la vacía', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const add = await screen.findByLabelText('Add Group')

    await elegir(user, add, 'Administrators')
    expect(screen.getByLabelText('Member Of')).toHaveValue('Administrators\n')

    await elegir(user, add, 'DNS Administrators')
    expect(screen.getByLabelText('Member Of')).toHaveValue('Administrators\nDNS Administrators\n')

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    // `cleanTextList`: saltos a comas, sin coma final.
    expect(body.memberOfGroups).toBe('Administrators,DNS Administrators')
  })

  it('un usuario de SSO tiene bloqueados nombre y nombre visible, y no los envía', async () => {
    const spy = servidor([USUARIO_SSO], {
      ...DETALLE_USUARIO,
      ...USUARIO_SSO,
      ssoManagedGroups: false,
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    expect(await screen.findByLabelText('Display Name')).toBeDisabled()
    expect(screen.getByLabelText('Username')).toBeDisabled()
    // Con `ssoManagedGroups` a falso los grupos SÍ se pueden tocar: son dos
    // condiciones distintas, no una.
    expect(screen.getByLabelText('Member Of')).not.toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.displayName).toBeUndefined()
    expect(body.newUser).toBeUndefined()
    expect(body.memberOfGroups).toBe('')
  })

  it('con `ssoManagedGroups` los grupos también quedan bloqueados y fuera del envío', async () => {
    const spy = servidor([USUARIO_SSO], {
      ...DETALLE_USUARIO,
      ...USUARIO_SSO,
      ssoManagedGroups: true,
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    expect(await screen.findByLabelText('Member Of')).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.memberOfGroups).toBeUndefined()
  })

  it('`newUser` sólo viaja cuando el nombre cambia', async () => {
    const spy = servidor([USUARIO_NUEVO])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const campo = await screen.findByLabelText('Username')
    await user.clear(campo)
    await user.type(campo, 'otro')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.newUser).toBe('otro')
  })

  it('las sesiones del usuario salen dentro del modal con su propio total', async () => {
    servidor([USUARIO_NUEVO], {
      ...DETALLE_USUARIO,
      sessions: [
        {
          username: 'testuser',
          isCurrentSession: false,
          partialToken: '799a4919af7636e2',
          type: 'ApiToken',
          tokenName: 'tok1',
          lastSeen: '2026-08-26T05:29:41Z',
          lastSeenRemoteAddress: '172.23.0.1',
          lastSeenUserAgent: 'curl/8.18.0',
        },
      ],
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const dialogo = await screen.findByRole('dialog')
    expect(within(dialogo).getByText('Total Sessions: 1')).toBeInTheDocument()
    expect(within(dialogo).getByText('[799a4919af7636e2]')).toBeInTheDocument()
  })
})
