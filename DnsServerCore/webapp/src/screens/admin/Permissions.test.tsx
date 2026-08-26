import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Permissions } from './Permissions'
import * as client from '../../api/client'
import { CLUSTER_PRIMARIO, PERMISOS } from './admin.fixture'
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
  // `Everyone` sale en esta lista y NO en la de `groups/list`: son dos listas
  // distintas del servidor.
  groups: ['Administrators', 'DHCP Administrators', 'Everyone'],
}

function servidor(secciones = PERMISOS, detalle: Record<string, unknown> = DETALLE) {
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

describe('Permissions — la lista', () => {
  it('pinta una tarjeta por sección con sus dos tablas y el total', async () => {
    servidor()
    render(<Permissions {...props} />)

    expect(await screen.findByRole('button', { name: 'Dashboard' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Zones' })).toBeInTheDocument()
    expect(screen.getByText('Total Sections: 2')).toBeInTheDocument()
    expect(screen.getAllByText('User Permissions')).toHaveLength(2)
    expect(screen.getAllByText('Group Permissions')).toHaveLength(2)
  })

  it('sin permisos por usuario sale el literal de upstream', async () => {
    servidor()
    render(<Permissions {...props} />)
    expect(await screen.findByText('No user permissions')).toBeInTheDocument()
  })

  it('sin permisos por grupo sale su propio literal', async () => {
    servidor([{ section: 'Logs', userPermissions: [], groupPermissions: [] }])
    render(<Permissions {...props} />)
    expect(await screen.findByText('No group permissions')).toBeInTheDocument()
  })

  it('la lista es de sólo lectura: sus casillas están deshabilitadas', async () => {
    servidor()
    render(<Permissions {...props} />)
    expect(await screen.findByLabelText('Dashboard Administrators View')).toBeDisabled()
    expect(screen.getByLabelText('Dashboard Everyone Modify')).not.toBeChecked()
  })

  it('sin secciones el total dice cero', async () => {
    servidor([])
    render(<Permissions {...props} />)
    expect(await screen.findByText('Total Sections: 0')).toBeInTheDocument()
  })
})

describe('Permissions — el modal de edición', () => {
  async function abrir(cluster = null as never) {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Permissions {...props} cluster={cluster} />)
    await user.click(await screen.findByRole('button', { name: 'Dashboard' }))
    await screen.findByRole('dialog')
    return { user, spy }
  }

  it('pide la sección con usuarios y grupos', async () => {
    const { spy } = await abrir()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/permissions/get')?.[1]).toEqual({
      token: 'tok',
      body: { section: 'Dashboard', includeUsersAndGroups: 'true' },
    })
  })

  it('serializa las dos tablas con `|` y manda el nodo primario del cluster', async () => {
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

  it('sin cluster el nodo viaja como cadena vacía', async () => {
    const { user, spy } = await abrir()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.node).toBe('')
  })

  it('«Add User» añade la fila con los tres permisos a falso', async () => {
    const { user, spy } = await abrir()
    await elegir(user, screen.getByLabelText('Add User'), 'testuser')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.userPermissions).toBe('testuser|false|false|false')
  })

  it('«None» vacía la tabla entera', async () => {
    const { user, spy } = await abrir()
    await elegir(user, screen.getByLabelText('Add Group'), 'None')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.groupPermissions).toBe('')
  })

  it('«Remove» quita una fila y marcar una casilla se refleja en el envío', async () => {
    const { user, spy } = await abrir()
    const dialogo = screen.getByRole('dialog')

    await user.click(within(dialogo).getByLabelText('Everyone Modify'))
    await user.click(within(dialogo).getAllByRole('button', { name: 'Remove' })[0])
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]?.body as Record<string, string>
    expect(body.groupPermissions).toBe('Everyone|true|true|false')
  })

  it('al guardar avisa con el literal de upstream y repinta la sección', async () => {
    const onAviso = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Permissions {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'Dashboard' }))
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Permissions Saved!',
      text: 'Section permissions were saved successfully.',
    })
  })
})
