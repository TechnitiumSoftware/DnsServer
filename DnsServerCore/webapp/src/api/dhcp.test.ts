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

/* Un scope tal y como lo devuelve de verdad una instancia v15.4 recién
   instalada: SIN `domainSearchList`, `serverAddress`, `serverHostName`,
   `bootFileName`, `winsServers`, `ntpServers`, `staticRoutes`, `vendorInfo`,
   `capwapAcIpAddresses`, `tftpServerAddresses` ni `genericOptions`. */
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

describe('api/dhcp — concesiones', () => {
  it('leases/list pide el nodo y devuelve la lista', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { leases: [{ scope: 'Default' }] } }))

    const leases = await listLeases('tok')

    const llamada = spy.mock.calls.find((c) => c[0] === 'dhcp/leases/list')!
    expect(llamada[1]).toMatchObject({ token: 'tok', body: { node: '' } })
    expect(leases.kind === 'ok' && leases.data).toHaveLength(1)
  })

  /*
  Esta prueba afirmaba lo contrario —«devuelve lista vacía si el servidor
  falla»— y estaba fijando el fallo: una lista vacía y una llamada caída se
  pintan igual, así que la pantalla decía «No Lease Found» cuando lo que
  había pasado es que no había respuesta. Ahora el fallo sube tal cual, con su
  mensaje, y es la pantalla la que decide qué enseñar.
  */
  it('leases/list sube el fallo del servidor, no una lista vacía', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listLeases('tok')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('y una lista vacía de verdad sigue siendo una lista vacía', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: { leases: [] } }))
    expect(await listLeases('tok')).toEqual({ kind: 'ok', data: [] })
  })

  it('las tres acciones sobre una concesión mandan scope y clientIdentifier', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await removeLease('tok', 'Default', '1-AA')
    await convertToReservedLease('tok', 'Default', '1-AA')
    await convertToDynamicLease('tok', 'Default', '1-AA')

    const cuerpo = { name: 'Default', clientIdentifier: '1-AA', node: '' }
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/remove')![1]?.body).toEqual(cuerpo)
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/convertToReserved')![1]?.body).toEqual(
      cuerpo,
    )
    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/leases/convertToDynamic')![1]?.body).toEqual(
      cuerpo,
    )
  })
})

describe('api/dhcp — scopes', () => {
  it('scopes/list pide el nodo y devuelve la lista', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { scopes: [{ name: 'Default' }] } }))

    const scopes = await listScopes('tok')

    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/scopes/list')![1]?.body).toEqual({ node: '' })
    expect(scopes.kind === 'ok' && scopes.data[0].name).toBe('Default')
  })

  /*
  Esta prueba afirmaba lo contrario —«devuelve lista vacía si el servidor
  falla»— y estaba fijando el fallo: una lista vacía y una llamada caída se
  pintan igual, así que la pantalla decía «No Scope Found» cuando lo que
  había pasado es que no había respuesta. Ahora el fallo sube tal cual, con su
  mensaje, y es la pantalla la que decide qué enseñar.
  */
  it('scopes/list sube el fallo del servidor, no una lista vacía', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listScopes('tok')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('scopes/get pide el nombre y devuelve el scope sin desenvolver de más', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: SCOPE_REAL }))

    const s = await getScope('tok', 'Default')

    expect(spy.mock.calls.find((c) => c[0] === 'dhcp/scopes/get')![1]?.body).toEqual({
      name: 'Default',
      node: '',
    })
    expect(s?.name).toBe('Default')
    // Las claves que el servidor omite siguen ausentes: no se inventan nulos.
    expect(s?.staticRoutes).toBeUndefined()
    expect(s?.winsServers).toBeUndefined()
  })

  it('scopes/get devuelve null si el servidor falla', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getScope('tok', 'Default')).toBeNull()
  })

  it('scopes/set va por POST, con el nodo en la QUERY y el resto en el cuerpo', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await setScope('tok', { name: 'Default' }, 'nodo-1')

    const llamada = spy.mock.calls.find((c) => String(c[0]).startsWith('dhcp/scopes/set'))!
    expect(llamada[0]).toBe('dhcp/scopes/set?node=nodo-1')
    expect(llamada[1]).toMatchObject({ method: 'POST', body: { name: 'Default' } })
    // El nodo NO se duplica en el cuerpo.
    expect(llamada[1]?.body).not.toHaveProperty('node')
  })

  it('enable, disable y delete mandan el nombre y el nodo', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))

    await enableScope('tok', 'Default')
    await disableScope('tok', 'Default')
    await deleteScope('tok', 'Default')

    for (const ruta of ['dhcp/scopes/enable', 'dhcp/scopes/disable', 'dhcp/scopes/delete']) {
      expect(spy.mock.calls.find((c) => c[0] === ruta)![1]?.body).toEqual({
        name: 'Default',
        node: '',
      })
    }
  })
})
