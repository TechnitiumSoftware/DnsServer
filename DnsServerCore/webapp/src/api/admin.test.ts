import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from './client'
import {
  createApiToken,
  createGroup,
  createUser,
  deleteAdminSession,
  deleteGroup,
  deleteUser,
  getGroup,
  getPermission,
  getSsoConfig,
  getUser,
  listGroups,
  listPermissions,
  listSessions,
  listUsers,
  resetUserPassword,
  setGroup,
  setPermissions,
  setSsoConfig,
  setUser,
} from './admin'

afterEach(() => vi.restoreAllMocks())

/** A spy over `apiRequest` that always returns `ok` with an empty payload. */
function espia() {
  return vi
    .spyOn(client, 'apiRequest')
    .mockResolvedValue({ kind: 'ok', data: { response: {}, server: 's' } })
}

describe('admin — sesiones', () => {
  it('lista mandando el nodo del cluster', async () => {
    const spy = espia()
    await listSessions('tok', 'ns1.test')
    expect(spy).toHaveBeenCalledWith('admin/sessions/list', {
      token: 'tok',
      body: { node: 'ns1.test' },
    })
  })

  it('sin cluster manda el nodo como cadena vacía, no lo omite', async () => {
    const spy = espia()
    await listSessions('tok')
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/list')?.[1]).toEqual({
      token: 'tok',
      body: { node: '' },
    })
  })

  it('crea un token de API con usuario y nombre', async () => {
    const spy = espia()
    await createApiToken('tok', 'adrian', 'orbiter')
    expect(spy).toHaveBeenCalledWith('admin/sessions/createToken', {
      token: 'tok',
      body: { user: 'adrian', tokenName: 'orbiter' },
    })
  })

  it('al borrar SIN nodo no manda el parámetro: es lo que hace el modal de detalles', async () => {
    const spy = espia()
    await deleteAdminSession('tok', 'abcd')
    expect(spy).toHaveBeenCalledWith('admin/sessions/delete', {
      token: 'tok',
      body: { partialToken: 'abcd' },
    })
  })

  it('al borrar con nodo vacío SÍ manda el parámetro: es lo que hace la pestaña', async () => {
    const spy = espia()
    await deleteAdminSession('tok', 'abcd', '')
    expect(spy).toHaveBeenCalledWith('admin/sessions/delete', {
      token: 'tok',
      body: { partialToken: 'abcd', node: '' },
    })
  })
})

describe('admin — usuarios', () => {
  it('lista sin parámetros', async () => {
    const spy = espia()
    await listUsers('tok')
    expect(spy).toHaveBeenCalledWith('admin/users/list', { token: 'tok' })
  })

  it('crea por POST, que es lo que hace upstream por llevar contraseña', async () => {
    const spy = espia()
    await createUser('tok', 'Adrián', 'adrian', 's3cr3t')
    expect(spy).toHaveBeenCalledWith('admin/users/create', {
      token: 'tok',
      method: 'POST',
      body: { displayName: 'Adrián', user: 'adrian', pass: 's3cr3t' },
    })
  })

  it('consulta pidiendo también la lista de grupos', async () => {
    const spy = espia()
    await getUser('tok', 'adrian')
    expect(spy).toHaveBeenCalledWith('admin/users/get', {
      token: 'tok',
      body: { user: 'adrian', includeGroups: 'true' },
    })
  })

  it('el cuerpo de `set` es abierto: sólo viaja lo que se quiere cambiar', async () => {
    const spy = espia()
    await setUser('tok', { user: 'adrian', disabled: 'true' })
    expect(spy).toHaveBeenCalledWith('admin/users/set', {
      token: 'tok',
      body: { user: 'adrian', disabled: 'true' },
    })
  })

  it('resetear la contraseña usa el mismo endpoint pero por POST', async () => {
    const spy = espia()
    await resetUserPassword('tok', 'adrian', 'nueva')
    expect(spy).toHaveBeenCalledWith('admin/users/set', {
      token: 'tok',
      method: 'POST',
      body: { user: 'adrian', newPass: 'nueva' },
    })
  })

  it('borra por nombre', async () => {
    const spy = espia()
    await deleteUser('tok', 'adrian')
    expect(spy).toHaveBeenCalledWith('admin/users/delete', { token: 'tok', body: { user: 'adrian' } })
  })
})

describe('admin — grupos', () => {
  it('lista, crea, consulta y borra', async () => {
    const spy = espia()
    await listGroups('tok')
    await createGroup('tok', 'Ops', 'los de guardia')
    await getGroup('tok', 'Ops')
    await deleteGroup('tok', 'Ops')

    expect(spy.mock.calls.map((c) => c[0])).toEqual([
      'admin/groups/list',
      'admin/groups/create',
      'admin/groups/get',
      'admin/groups/delete',
    ])
    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/create')?.[1]).toEqual({
      token: 'tok',
      body: { group: 'Ops', description: 'los de guardia' },
    })
    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/get')?.[1]).toEqual({
      token: 'tok',
      body: { group: 'Ops', includeUsers: 'true' },
    })
  })

  it('`newGroup` NO viaja si el nombre no cambió', async () => {
    const spy = espia()
    await setGroup('tok', 'Ops', 'desc', 'a,b')
    expect(spy).toHaveBeenCalledWith('admin/groups/set', {
      token: 'tok',
      body: { group: 'Ops', description: 'desc', members: 'a,b' },
    })
  })

  it('`newGroup` viaja cuando el nombre cambió', async () => {
    const spy = espia()
    await setGroup('tok', 'Ops', 'desc', 'a,b', 'Ops2')
    expect(spy.mock.calls[0][1]).toEqual({
      token: 'tok',
      body: { group: 'Ops', description: 'desc', members: 'a,b', newGroup: 'Ops2' },
    })
  })
})

describe('admin — permisos', () => {
  it('consulta pidiendo usuarios y grupos', async () => {
    const spy = espia()
    await getPermission('tok', 'Zones')
    expect(spy).toHaveBeenCalledWith('admin/permissions/get', {
      token: 'tok',
      body: { section: 'Zones', includeUsersAndGroups: 'true' },
    })
  })

  it('guarda las dos tablas serializadas y el nodo PRIMARIO del cluster', async () => {
    const spy = espia()
    await listPermissions('tok')
    await setPermissions('tok', 'Zones', 'ana|true|false|false', 'Ops|true|true|true', 'ns1.test')
    expect(spy.mock.calls.find((c) => c[0] === 'admin/permissions/set')?.[1]).toEqual({
      token: 'tok',
      body: {
        section: 'Zones',
        userPermissions: 'ana|true|false|false',
        groupPermissions: 'Ops|true|true|true',
        node: 'ns1.test',
      },
    })
  })
})

describe('admin — SSO', () => {
  it('lee pidiendo los grupos locales', async () => {
    const spy = espia()
    await getSsoConfig('tok')
    expect(spy).toHaveBeenCalledWith('admin/sso/get', {
      token: 'tok',
      body: { includeGroups: 'true' },
    })
  })

  it('guarda por POST', async () => {
    const spy = espia()
    await setSsoConfig('tok', { ssoEnabled: 'false' })
    expect(spy).toHaveBeenCalledWith('admin/sso/set', {
      token: 'tok',
      method: 'POST',
      body: { ssoEnabled: 'false' },
    })
  })
})
