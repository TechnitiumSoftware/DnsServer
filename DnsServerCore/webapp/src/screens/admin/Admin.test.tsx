import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Admin, SUBPESTANAS } from './Admin'
import * as client from '../../api/client'
import { CLUSTER_SIN_INICIAR, GROUPS, PERMISSIONS, SESION_ADMIN, SSO, USUARIO_ADMIN } from './admin.fixture'

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
        return ok({ response: { groups: GROUPS }, server: 'x' })
      case 'admin/permissions/list':
        return ok({ response: { permissions: PERMISSIONS }, server: 'x' })
      case 'admin/sso/get':
        return ok({ response: SSO, server: 'x' })
      case 'admin/cluster/state':
        return ok({ response: CLUSTER_SIN_INICIAR, server: 'x' })
      default:
        return ok({ response: {}, server: 'x' })
    }
  })
}

describe('Admin — the sub-navigation belongs to the Shell', () => {
  it('with no `sub` it starts on Sessions, just like upstream', async () => {
    servidor()
    render(<Admin token="tok" />)
    expect(await screen.findByRole('heading', { name: 'Sessions' })).toBeInTheDocument()
  })

  it('a sub-tab that does not exist falls to Sessions instead of going blank', async () => {
    servidor()
    render(<Admin token="tok" sub="Inventada" />)
    expect(await screen.findByRole('heading', { name: 'Sessions' })).toBeInTheDocument()
  })

  it('the six sub-tabs draw without breaking and only one at a time', async () => {
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

  it('the cluster state is asked for ONCE and the sub-tabs share it', async () => {
    const spy = servidor()
    render(<Admin token="tok" sub="Users" />)
    await screen.findByText('Total Users: 1')
    expect(spy.mock.calls.filter((c) => c[0] === 'admin/cluster/state')).toHaveLength(1)
  })

  it('if the cluster state fails, the section keeps working', async () => {
    vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'admin/cluster/state') return { kind: 'error' as const, message: 'boom' }
      if (path === 'admin/groups/list') return ok({ response: { groups: GROUPS }, server: 'x' })
      return ok({ response: {}, server: 'x' })
    })
    render(<Admin token="tok" sub="Groups" />)
    expect(await screen.findByText('Total Groups: 3')).toBeInTheDocument()
  })
})
