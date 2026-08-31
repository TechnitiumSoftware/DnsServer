import { describe, expect, it, vi, afterEach } from 'vitest'
import * as client from './client'
import {
  convertToDynamicLease,
  convertToReservedLease,
  deleteScope,
  disableScope,
  enableScope,
  getScope,
  listLeases,
  listScopes,
  removeLease,
  setScope,
  type DhcpScope,
} from './dhcp'

afterEach(() => vi.restoreAllMocks())

function ok(data: unknown) {
  return { kind: 'ok' as const, data }
}

/* A scope exactly as a freshly installed v15.4 instance really returns it:
   WITHOUT `domainSearchList`, `serverAddress`, `serverHostName`, `bootFileName`,
   `winsServers`, `ntpServers`, `staticRoutes`, `vendorInfo`,
   `capwapAcIpAddresses`, `tftpServerAddresses` or `genericOptions`. */
const SCOPE_REAL: DhcpScope = {
  name: 'Default',
  startingAddress: '192.168.1.1',
  endingAddress: '192.168.1.254',
  subnetMask: '255.255.255.0',
  leaseTimeDays: 1,
  leaseTimeHours: 0,
  leaseTimeMinutes: 0,
  offerDelayTime: 0,
  pingCheckEnabled: false,
  pingCheckTimeout: 1000,
  pingCheckRetries: 2,
  domainName: 'home',
  dnsUpdates: true,
  dnsOverwriteForDynamicLease: false,
  dnsTtl: 900,
  routerAddress: '192.168.1.1',
  useThisDnsServer: true,
  dnsServers: ['172.23.0.2'],
  exclusions: [{ startingAddress: '192.168.1.1', endingAddress: '192.168.1.10' }],
  reservedLeases: [],
  allowOnlyReservedLeases: false,
  blockLocallyAdministeredMacAddresses: false,
  ignoreClientIdentifierOption: true,
}

describe('api/dhcp — leases', () => {
  it('leases/list asks for the node and returns the list', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { leases: [{ scope: 'Default' }] } }))

    const leases = await listLeases('tok')

    const call = spy.mock.calls.find((c) => c[0] === 'dhcp/leases/list')!
    expect(call[1]).toMatchObject({ token: 'tok', body: { node: '' } })
    expect(leases.kind === 'ok' && leases.data).toHaveLength(1)
  })

  /*
  This test claimed the opposite —"returns an empty list if the server fails"—
  and was pinning the bug in place: an empty list and a fallen call draw the
  same, so the screen said "No Lease Found" when what had happened was that
  there was no response. Now the failure rises as it is, with its message, and it
  is the screen that decides what to show.
  */
  it('leases/list raises the failure from the server, not an empty list', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listLeases('tok')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('and a genuinely empty list is still an empty list', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: { leases: [] } }))
    expect(await listLeases('tok')).toEqual({ kind: 'ok', data: [] })
  })

  it('the three actions on a lease send scope and clientIdentifier', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await removeLease('tok', 'Default', '1-AA')
    await convertToReservedLease('tok', 'Default', '1-AA')
    await convertToDynamicLease('tok', 'Default', '1-AA')

    const body = { name: 'Default', clientIdentifier: '1-AA', node: '' }
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/remove')![1]?.body).toEqual(body)
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/convertToReserved')![1]?.body).toEqual(
      body,
    )
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/convertToDynamic')![1]?.body).toEqual(
      body,
    )
  })
})

describe('api/dhcp — scopes', () => {
  it('scopes/list asks for the node and returns the list', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { scopes: [{ name: 'Default' }] } }))

    const scopes = await listScopes('tok')

    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/scopes/list')![1]?.body).toEqual({ node: '' })
    expect(scopes.kind === 'ok' && scopes.data[0].name).toBe('Default')
  })

  /*
  This test claimed the opposite —"returns an empty list if the server fails"—
  and was pinning the bug in place: an empty list and a fallen call draw the
  same, so the screen said "No Scope Found" when what had happened was that
  there was no response. Now the failure rises as it is, with its message, and it
  is the screen that decides what to show.
  */
  it('scopes/list raises the failure from the server, not an empty list', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listScopes('tok')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('scopes/get asks for the name and returns the scope without over-unwrapping', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: SCOPE_REAL }))

    const s = await getScope('tok', 'Default')

    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/scopes/get')![1]?.body).toEqual({
      name: 'Default',
      node: '',
    })
    expect(s?.name).toBe('Default')
    // The keys the server omits stay absent: no nulls are invented.
    expect(s?.staticRoutes).toBeUndefined()
    expect(s?.winsServers).toBeUndefined()
  })

  it('scopes/get returns null if the server fails', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getScope('tok', 'Default')).toBeNull()
  })

  it('scopes/set goes by POST, with the node in the QUERY and the rest in the body', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await setScope('tok', { name: 'Default' }, 'nodo-1')

    const call = spy.mock.calls.find((c) => String(c[0]).startsWith('dhcp/scopes/set'))!
    expect(call[0]).toBe('dhcp/scopes/set?node=nodo-1')
    expect(call[1]).toMatchObject({ method: 'POST', body: { name: 'Default' } })
    // The node is NOT duplicated in the body.
    expect(call[1]?.body).not.toHaveProperty('node')
  })

  it('enable, disable and delete send the name and the node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await enableScope('tok', 'Default')
    await disableScope('tok', 'Default')
    await deleteScope('tok', 'Default')

    for (const route of ['dhcp/scopes/enable', 'dhcp/scopes/disable', 'dhcp/scopes/delete']) {
      expect(spy.mock.calls.find((c) => c[0] === route)![1]?.body).toEqual({
        name: 'Default',
        node: '',
      })
    }
  })
})
