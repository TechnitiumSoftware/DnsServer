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
function makeSpy() {
  return vi
    .spyOn(client, 'apiRequest')
    .mockResolvedValue({ kind: 'ok', data: { response: {}, server: 's' } })
}

describe('admin — sessions', () => {
  it('lists sending the cluster node', async () => {
    const spy = makeSpy()
    await listSessions('tok', 'ns1.test')
    expect(spy).toHaveBeenCalledWith('admin/sessions/list', {
      token: 'tok',
      body: { node: 'ns1.test' },
    })
  })

  it('with no cluster it sends the node as an empty string, it does not omit it', async () => {
    const spy = makeSpy()
    await listSessions('tok')
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sessions/list')?.[1]).toEqual({
      token: 'tok',
      body: { node: '' },
    })
  })

  it('creates an API token with a user and a name', async () => {
    const spy = makeSpy()
    await createApiToken('tok', 'adrian', 'orbiter')
    expect(spy).toHaveBeenCalledWith('admin/sessions/createToken', {
      token: 'tok',
      body: { user: 'adrian', tokenName: 'orbiter' },
    })
  })

  it('deleting WITHOUT a node does not send the parameter: that is what the details modal does', async () => {
    const spy = makeSpy()
    await deleteAdminSession('tok', 'abcd')
    expect(spy).toHaveBeenCalledWith('admin/sessions/delete', {
      token: 'tok',
      body: { partialToken: 'abcd' },
    })
  })

  it('deleting with an empty node DOES send the parameter: that is what the tab does', async () => {
    const spy = makeSpy()
    await deleteAdminSession('tok', 'abcd', '')
    expect(spy).toHaveBeenCalledWith('admin/sessions/delete', {
      token: 'tok',
      body: { partialToken: 'abcd', node: '' },
    })
  })
})

describe('admin — users', () => {
  it('lists with no parameters', async () => {
    const spy = makeSpy()
    await listUsers('tok')
    expect(spy).toHaveBeenCalledWith('admin/users/list', { token: 'tok' })
  })

  it('creates by POST, which is what upstream does since it carries a password', async () => {
    const spy = makeSpy()
    await createUser('tok', 'Adrián', 'adrian', 's3cr3t')
    expect(spy).toHaveBeenCalledWith('admin/users/create', {
      token: 'tok',
      method: 'POST',
      body: { displayName: 'Adrián', user: 'adrian', pass: 's3cr3t' },
    })
  })

  it('reads asking for the group list as well', async () => {
    const spy = makeSpy()
    await getUser('tok', 'adrian')
    expect(spy).toHaveBeenCalledWith('admin/users/get', {
      token: 'tok',
      body: { user: 'adrian', includeGroups: 'true' },
    })
  })

  it('the body of `set` is open: only what you want to change travels', async () => {
    const spy = makeSpy()
    await setUser('tok', { user: 'adrian', disabled: 'true' })
    expect(spy).toHaveBeenCalledWith('admin/users/set', {
      token: 'tok',
      body: { user: 'adrian', disabled: 'true' },
    })
  })

  it('resetting the password uses the same endpoint but by POST', async () => {
    const spy = makeSpy()
    await resetUserPassword('tok', 'adrian', 'nueva')
    expect(spy).toHaveBeenCalledWith('admin/users/set', {
      token: 'tok',
      method: 'POST',
      body: { user: 'adrian', newPass: 'nueva' },
    })
  })

  it('deletes by name', async () => {
    const spy = makeSpy()
    await deleteUser('tok', 'adrian')
    expect(spy).toHaveBeenCalledWith('admin/users/delete', { token: 'tok', body: { user: 'adrian' } })
  })
})

describe('admin — groups', () => {
  it('lists, creates, reads and deletes', async () => {
    const spy = makeSpy()
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

  it('`newGroup` does NOT travel if the name did not change', async () => {
    const spy = makeSpy()
    await setGroup('tok', 'Ops', 'desc', 'a,b')
    expect(spy).toHaveBeenCalledWith('admin/groups/set', {
      token: 'tok',
      body: { group: 'Ops', description: 'desc', members: 'a,b' },
    })
  })

  it('`newGroup` travels when the name changed', async () => {
    const spy = makeSpy()
    await setGroup('tok', 'Ops', 'desc', 'a,b', 'Ops2')
    expect(spy.mock.calls[0][1]).toEqual({
      token: 'tok',
      body: { group: 'Ops', description: 'desc', members: 'a,b', newGroup: 'Ops2' },
    })
  })
})

describe('admin — permissions', () => {
  it('reads asking for users and groups', async () => {
    const spy = makeSpy()
    await getPermission('tok', 'Zones')
    expect(spy).toHaveBeenCalledWith('admin/permissions/get', {
      token: 'tok',
      body: { section: 'Zones', includeUsersAndGroups: 'true' },
    })
  })

  it('saves both tables serialised and the PRIMARY node of the cluster', async () => {
    const spy = makeSpy()
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
  it('reads asking for the local groups', async () => {
    const spy = makeSpy()
    await getSsoConfig('tok')
    expect(spy).toHaveBeenCalledWith('admin/sso/get', {
      token: 'tok',
      body: { includeGroups: 'true' },
    })
  })

  it('saves by POST', async () => {
    const spy = makeSpy()
    await setSsoConfig('tok', { ssoEnabled: 'false' })
    expect(spy).toHaveBeenCalledWith('admin/sso/set', {
      token: 'tok',
      method: 'POST',
      body: { ssoEnabled: 'false' },
    })
  })
})
