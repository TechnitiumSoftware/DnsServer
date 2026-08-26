import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sessions } from './Sessions'
import * as client from '../../api/client'
import {
  CLUSTER_PRIMARIO,
  CLUSTER_SIN_INICIAR,
  SESION_ADMIN,
  SESION_TOKEN,
  USUARIO_ADMIN,
  USUARIO_NUEVO,
} from './admin.fixture'
import { elegir } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(overrides: Record<string, unknown> = {}, server = 'ref.technitium-ui.test') {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/sessions/list') {
      return ok({ response: { sessions: [SESION_ADMIN, SESION_TOKEN] }, server, ...overrides })
    }
    if (path === 'admin/users/list') {
      return ok({ response: { users: [USUARIO_ADMIN, USUARIO_NUEVO] }, server })
    }
    if (path === 'admin/sessions/createToken') {
      return ok({
        response: { username: 'testuser', tokenName: 'orbiter', token: 'abc123' },
        server,
      })
    }
    return ok({ response: {}, server })
  })
}

const props = { token: 'tok', cluster: null, onAviso: vi.fn() }

describe('Sessions — la tabla', () => {
  it('pinta cada sesión con su token parcial, su tipo y el total', async () => {
    servidor()
    render(<Sessions {...props} />)

    expect(await screen.findByText('[5fc1a6bc90cc1d9a]')).toBeInTheDocument()
    expect(screen.getByText('(current)')).toBeInTheDocument()
    expect(screen.getByText('Standard')).toBeInTheDocument()
    expect(screen.getByText('API Token')).toBeInTheDocument()
    expect(screen.getByText('tok1')).toBeInTheDocument()
    expect(screen.getByText('Total Sessions: 2')).toBeInTheDocument()
  })

  it('un tipo de sesión que no conoce no se calla: sale como «Unknown»', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({
        response: { sessions: [{ ...SESION_ADMIN, type: 'Marciana' }] },
        server: 'x',
      }),
    )
    render(<Sessions {...props} />)
    expect(await screen.findByText('Unknown')).toBeInTheDocument()
  })

  it('sin sesiones la tabla queda vacía y el total dice cero', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: { sessions: [] }, server: 'x' }))
    render(<Sessions {...props} />)
    expect(await screen.findByText('Total Sessions: 0')).toBeInTheDocument()
  })

  it('si el servidor falla avisa con SU mensaje y no revienta', async () => {
    const onAviso = vi.fn()
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Access was denied.' })
    render(<Sessions {...props} onAviso={onAviso} />)

    expect(await screen.findByText('Total Sessions: 0')).toBeInTheDocument()
    expect(onAviso).toHaveBeenCalledWith({
      type: 'danger',
      title: 'Error!',
      text: 'Access was denied.',
    })
  })
})

describe('Sessions — «Create Token»', () => {
  it('se ve cuando no hay cluster', async () => {
    servidor()
    render(<Sessions {...props} />)
    expect(await screen.findByRole('button', { name: 'Create Token' })).toBeInTheDocument()
  })

  it('se ve si este servidor ES el nodo primario', async () => {
    servidor({}, 'ns1.micluster.test')
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)
    expect(await screen.findByRole('button', { name: 'Create Token' })).toBeInTheDocument()
  })

  it('se esconde si este servidor NO es el nodo primario', async () => {
    servidor({}, 'ns2.micluster.test')
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)
    await screen.findByText('Total Sessions: 2')
    expect(screen.queryByRole('button', { name: 'Create Token' })).not.toBeInTheDocument()
  })

  it('exige primero el usuario y después el nombre del token', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Create Token' }))
    await screen.findByLabelText('Token Name')

    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(screen.getByText('Please enter a token name.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/createToken')).toBeUndefined()
  })

  it('crea el token y enseña usuario, nombre y token', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Create Token' }))
    await user.type(await screen.findByLabelText('Token Name'), 'orbiter')
    await elegir(user, screen.getByLabelText('Username'), 'testuser')
    await user.click(screen.getByRole('button', { name: 'Create' }))

    const llamada = spy.mock.calls.find((c) => c[0] === 'admin/sessions/createToken')
    expect(llamada?.[1]).toEqual({ token: 'tok', body: { user: 'testuser', tokenName: 'orbiter' } })
    expect(await screen.findByText('API token was created successfully.')).toBeInTheDocument()
    expect(screen.getByLabelText('Token')).toHaveValue('abc123')
  })
})

describe('Sessions — borrar una sesión', () => {
  it('pide confirmación con el token parcial en el texto', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click((await screen.findAllByRole('button', { name: 'Delete Session' }))[0])
    expect(
      screen.getByText('Are you sure you want to delete the session [5fc1a6bc90cc1d9a] ?'),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')).toBeUndefined()
  })

  it('una sesión normal se borra con el nodo ELEGIDO en la pantalla', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} cluster={CLUSTER_SIN_INICIAR} />)

    await user.click((await screen.findAllByRole('button', { name: 'Delete Session' }))[0])
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')?.[1]).toEqual({
      token: 'tok',
      body: { partialToken: '5fc1a6bc90cc1d9a', node: '' },
    })
  })

  it('un token de API se borra contra el nodo PRIMARIO, no contra el elegido', async () => {
    const spy = servidor({}, 'ns1.micluster.test')
    const user = userEvent.setup()
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)

    await user.click((await screen.findAllByRole('button', { name: 'Delete Session' }))[1])
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')?.[1]).toEqual({
      token: 'tok',
      body: { partialToken: '799a4919af7636e2', node: 'ns1.micluster.test' },
    })
  })

  it('al borrar, el aviso de éxito es el literal de upstream y sale en la página', async () => {
    const onAviso = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} onAviso={onAviso} />)

    await user.click((await screen.findAllByRole('button', { name: 'Delete Session' }))[0])
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
    expect(screen.getByText('Total Sessions: 1')).toBeInTheDocument()
  })
})
