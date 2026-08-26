import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Admin, SUBPESTANAS } from './Admin'
import * as client from '../../api/client'
import { CLUSTER_SIN_INICIAR, GRUPOS, PERMISOS, SESION_ADMIN, SSO, USUARIO_ADMIN } from './admin.fixture'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor() {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    switch (path) {
      case 'admin/sessions/list':
        return ok({ response: { sessions: [SESION_ADMIN] }, server: 'x' })
      case 'admin/users/list':
        return ok({ response: { users: [USUARIO_ADMIN] }, server: 'x' })
      case 'admin/groups/list':
        return ok({ response: { groups: GRUPOS }, server: 'x' })
      case 'admin/permissions/list':
        return ok({ response: { permissions: PERMISOS }, server: 'x' })
      case 'admin/sso/get':
        return ok({ response: SSO, server: 'x' })
      case 'admin/cluster/state':
        return ok({ response: CLUSTER_SIN_INICIAR, server: 'x' })
      default:
        return ok({ response: {}, server: 'x' })
    }
  })
}

describe('Admin — la sub-navegación es del Shell', () => {
  it('sin `sub` arranca en Sessions, igual que upstream', async () => {
    servidor()
    render(<Admin token="tok" />)
    expect(await screen.findByRole('heading', { name: 'Sessions' })).toBeInTheDocument()
  })

  it('una sub-pestaña que no existe cae en Sessions en vez de quedarse en blanco', async () => {
    servidor()
    render(<Admin token="tok" sub="Inventada" />)
    expect(await screen.findByRole('heading', { name: 'Sessions' })).toBeInTheDocument()
  })

  it('las seis sub-pestañas pintan sin romperse y sólo una a la vez', async () => {
    const marcas: Record<string, string> = {
      Sessions: 'Total Sessions: 1',
      Users: 'Total Users: 1',
      Groups: 'Total Groups: 3',
      Permissions: 'Total Sections: 2',
      SSO: 'Single Sign-On (SSO)',
      Cluster: 'Cluster Not Initialized',
    }
    for (const sub of SUBPESTANAS) {
      servidor()
      const { unmount } = render(<Admin token="tok" sub={sub} />)
      expect(await screen.findAllByText(marcas[sub])).not.toHaveLength(0)
      unmount()
      vi.restoreAllMocks()
    }
  })

  it('el estado del cluster se pide UNA vez y lo comparten las sub-pestañas', async () => {
    const spy = servidor()
    render(<Admin token="tok" sub="Users" />)
    await screen.findByText('Total Users: 1')
    expect(spy.mock.calls.filter((c) => c[0] === 'admin/cluster/state')).toHaveLength(1)
  })

  it('si el estado del cluster falla, la sección sigue funcionando', async () => {
    vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'admin/cluster/state') return { kind: 'error' as const, message: 'boom' }
      if (path === 'admin/groups/list') return ok({ response: { groups: GRUPOS }, server: 'x' })
      return ok({ response: {}, server: 'x' })
    })
    render(<Admin token="tok" sub="Groups" />)
    expect(await screen.findByText('Total Groups: 3')).toBeInTheDocument()
  })
})
