import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Permissions } from './Permissions'
import * as client from '../../api/client'
import { CLUSTER_PRIMARIO, PERMISSIONS } from './admin.fixture'
import { elegir } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

const DETALLE = {
  section: 'Dashboard',
  userPermissions: [],
  groupPermissions: [
    { name: 'Administrators', canView: true, canModify: true, canDelete: true },
    { name: 'Everyone', canView: true, canModify: false, canDelete: false },
  ],
  users: ['admin', 'testuser'],
  // `Everyone` appears in this list and NOT in `groups/list`'s: they are two
  // different lists from the server.
  groups: ['Administrators', 'DHCP Administrators', 'Everyone'],
}

function servidor(secciones = PERMISSIONS, detalle: Record<string, unknown> = DETALLE) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/permissions/list') {
      return ok({ response: { permissions: secciones }, server: 'x' })
    }
    if (path === 'admin/permissions/get') return ok({ response: detalle, server: 'x' })
    if (path === 'admin/permissions/set') {
      return ok({
        response: { section: 'Dashboard', userPermissions: [], groupPermissions: [] },
        server: 'x',
      })
    }
    return ok({ response: {}, server: 'x' })
  })
}

const props = { token: 'tok', cluster: null, onAviso: vi.fn() }

describe('Permissions — the list', () => {
  it('it draws one card per section with its two tables and the total', async () => {
    servidor()
    render(<Permissions {...props} />)

    /* The section's name is the panel's TITLE, not a button: it was an
       orange link and did the same thing as the "Edit Permissions" next to it
       —two controls for one action. Upstream does not link it either. */
    expect(await screen.findByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Zones')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Edit Permissions' })).toHaveLength(2)
    expect(screen.getByText('Total Sections: 2')).toBeInTheDocument()
    expect(screen.getAllByText('User Permissions')).toHaveLength(2)
    expect(screen.getAllByText('Group Permissions')).toHaveLength(2)
  })

  it('with no per-user permissions the upstream literal comes out', async () => {
    servidor()
    render(<Permissions {...props} />)
    expect(await screen.findByText('No user permissions')).toBeInTheDocument()
  })

  it('with no per-group permissions its own literal comes out', async () => {
    servidor([{ section: 'Logs', userPermissions: [], groupPermissions: [] }])
    render(<Permissions {...props} />)
    expect(await screen.findByText('No group permissions')).toBeInTheDocument()
  })

  it('the list is read-only: its checkboxes are disabled', async () => {
    servidor()
    render(<Permissions {...props} />)
    expect(await screen.findByLabelText('Dashboard Administrators View')).toBeDisabled()
    expect(screen.getByLabelText('Dashboard Everyone Modify')).not.toBeChecked()
  })

  it('with no sections the total says zero', async () => {
    servidor([])
    render(<Permissions {...props} />)
    expect(await screen.findByText('Total Sections: 0')).toBeInTheDocument()
  })
})

describe('Permissions — the editing modal', () => {
  async function abrir(cluster = null as never) {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Permissions {...props} cluster={cluster} />)
    // It opens through its panel's button, which is the only control left.
    const titulo = await screen.findByText('Dashboard')
    const panel = titulo.closest<HTMLElement>('[class*="_perm_"]')!
    await user.click(within(panel).getByRole('button', { name: 'Edit Permissions' }))
    await screen.findByRole('dialog')
    return { user, spy }
  }

  it('it asks for the section with users and groups', async () => {
    const { spy } = await abrir()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/permissions/get')?.[1]).toEqual({
      token: 'tok',
      body: { section: 'Dashboard', includeUsersAndGroups: 'true' },
    })
  })

  it('it serialises both tables with `|` and sends the primary node of the cluster', async () => {
    const { user, spy } = await abrir(CLUSTER_PRIMARIO as never)
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]).toEqual({
      token: 'tok',
      body: {
        section: 'Dashboard',
        userPermissions: '',
        groupPermissions:
          'Administrators|true|true|true|Everyone|true|false|false',
        node: 'ns1.micluster.test',
      },
    })
  })

  it('with no cluster the node travels as an empty string', async () => {
    const { user, spy } = await abrir()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.node).toBe('')
  })

  it('\"Add User\" adds the row with the three permissions false', async () => {
    const { user, spy } = await abrir()
    await elegir(user, screen.getByLabelText('Add User'), 'testuser')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.userPermissions).toBe('testuser|false|false|false')
  })

  it('\"None\" empties the whole table', async () => {
    const { user, spy } = await abrir()
    await elegir(user, screen.getByLabelText('Add Group'), 'None')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.groupPermissions).toBe('')
  })

  it('\"Remove\" takes a row out and checking a box shows up in the send', async () => {
    const { user, spy } = await abrir()
    const dialogo = screen.getByRole('dialog')

    await user.click(within(dialogo).getByLabelText('Everyone Modify'))
    await user.click(within(dialogo).getAllByRole('button', { name: 'Remove' })[0])
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.groupPermissions).toBe('Everyone|true|true|false')
  })

  it('on saving it alerts with the upstream literal and redraws the section', async () => {
    const onAviso = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Permissions {...props} onAviso={onAviso} />)

    const panel = (await screen.findByText('Dashboard')).closest<HTMLElement>('[class*="_perm_"]')!
    await user.click(within(panel).getByRole('button', { name: 'Edit Permissions' }))
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Permissions Saved!',
      text: 'Section permissions were saved successfully.',
    })
  })
})
