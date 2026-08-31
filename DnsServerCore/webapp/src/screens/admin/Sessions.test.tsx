import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sessions } from './Sessions'
import * as client from '../../api/client'
import {
  CLUSTER_PRIMARIO,
  CLUSTER_SIN_INICIAR,
  ADMIN_SESSION,
  TOKEN_SESSION,
  ADMIN_USER,
  NEW_USER,
} from './admin.fixture'
import { choose } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(overrides: Record<string, unknown> = {}, server = 'ref.technitium-ui.test') {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/sessions/list') {
      return ok({ response: { sessions: [ADMIN_SESSION, TOKEN_SESSION] }, server, ...overrides })
    }
    if (path === 'admin/users/list') {
      return ok({ response: { users: [ADMIN_USER, NEW_USER] }, server })
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

const props = { token: 'tok', cluster: null, onNotice: vi.fn() }

describe('Sessions — the table', () => {
  it('it draws each session with its partial token, its type and the total', async () => {
    servidor()
    render(<Sessions {...props} />)

    expect(await screen.findByText('[5fc1a6bc90cc1d9a]')).toBeInTheDocument()
    expect(screen.getByText('(current)')).toBeInTheDocument()
    expect(screen.getByText('Standard')).toBeInTheDocument()
    expect(screen.getByText('API Token')).toBeInTheDocument()
    expect(screen.getByText('tok1')).toBeInTheDocument()
    expect(screen.getByText('Total Sessions: 2')).toBeInTheDocument()
  })

  it('a session type it does not know is not swallowed: it comes out as \"Unknown\"', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({
        response: { sessions: [{ ...ADMIN_SESSION, type: 'Marciana' }] },
        server: 'x',
      }),
    )
    render(<Sessions {...props} />)
    expect(await screen.findByText('Unknown')).toBeInTheDocument()
  })

  it('with no sessions the table is left empty and the total says zero', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: { sessions: [] }, server: 'x' }))
    render(<Sessions {...props} />)
    expect(await screen.findByText('Total Sessions: 0')).toBeInTheDocument()
  })

  it('if the server fails it alerts with ITS message and does not blow up', async () => {
    const onNotice = vi.fn()
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Access was denied.' })
    render(<Sessions {...props} onNotice={onNotice} />)

    expect(await screen.findByText('Total Sessions: 0')).toBeInTheDocument()
    expect(onNotice).toHaveBeenCalledWith({
      type: 'danger',
      title: 'Error!',
      text: 'Access was denied.',
    })
  })
})

describe('Sessions — "Create Token"', () => {
  it('it shows when there is no cluster', async () => {
    servidor()
    render(<Sessions {...props} />)
    expect(await screen.findByRole('button', { name: 'Create Token' })).toBeInTheDocument()
  })

  it('it shows if this server IS the primary node', async () => {
    servidor({}, 'ns1.micluster.test')
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)
    expect(await screen.findByRole('button', { name: 'Create Token' })).toBeInTheDocument()
  })

  it('it hides if this server is NOT the primary node', async () => {
    servidor({}, 'ns2.micluster.test')
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)
    await screen.findByText('Total Sessions: 2')
    expect(screen.queryByRole('button', { name: 'Create Token' })).not.toBeInTheDocument()
  })

  it('it requires the user first and the token name second', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Create Token' }))
    await screen.findByLabelText('Token Name')

    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(screen.getByText('Please enter a token name.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/createToken')).toBeUndefined()
  })

  it('it creates the token and shows user, name and token', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Create Token' }))
    await user.type(await screen.findByLabelText('Token Name'), 'orbiter')
    await choose(user, screen.getByLabelText('Username'), 'testuser')
    await user.click(screen.getByRole('button', { name: 'Create' }))

    const call = spy.mock.calls.find((c) => c[0] === 'admin/sessions/createToken')
    expect(call?.[1]).toEqual({ token: 'tok', body: { user: 'testuser', tokenName: 'orbiter' } })
    expect(await screen.findByText('API token was created successfully.')).toBeInTheDocument()
    expect(screen.getByLabelText('Token')).toHaveValue('abc123')
  })
})

describe('Sessions — deleting a session', () => {
  it('it asks for confirmation with the partial token in the text', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Delete Session' }))
    expect(
      screen.getByText('Are you sure you want to delete the session [5fc1a6bc90cc1d9a] ?'),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')).toBeUndefined()
  })

  it('an ordinary session is deleted with the node CHOSEN on the screen', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} cluster={CLUSTER_SIN_INICIAR} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Delete Session' }))
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')?.[1]).toEqual({
      token: 'tok',
      body: { partialToken: '5fc1a6bc90cc1d9a', node: '' },
    })
  })

  it('an API token is deleted against the PRIMARY node, not the chosen one', async () => {
    const spy = servidor({}, 'ns1.micluster.test')
    const user = userEvent.setup()
    render(<Sessions {...props} cluster={CLUSTER_PRIMARIO} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[1])
    await user.click(await screen.findByRole('button', { name: 'Delete Session' }))
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/delete')?.[1]).toEqual({
      token: 'tok',
      body: { partialToken: '799a4919af7636e2', node: 'ns1.micluster.test' },
    })
  })

  it('on deleting, the success alert is the upstream literal and comes out on the page', async () => {
    const onNotice = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Sessions {...props} onNotice={onNotice} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Delete Session' }))
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
    expect(screen.getByText('Total Sessions: 1')).toBeInTheDocument()
  })
})
