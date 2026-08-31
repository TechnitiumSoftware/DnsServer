import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  getRecords,
  addRecord,
  deleteRecord,
  recordIdentity,
  aplanarSvcParams,
  aplanarGlue,
  cuerpoBorrado,
  cuerpoCambioDeEstado,
  fullDomain,
  zoneHasSvcbAutoHint,
  type ResourceRecord,
} from './records'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())
const env = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

/** A record with the bare minimum, so as not to repeat twelve fields in each case. */
function reg(type: string, rData: Record<string, unknown>, extra: Partial<ResourceRecord> = {}): ResourceRecord {
  return {
    name: 'www',
    type,
    ttl: 3600,
    ttlString: '1h',
    disabled: false,
    rData,
    dnssecStatus: 'Unknown',
    lastUsedOn: '0001-01-01T00:00:00',
    lastModified: '2026-08-26T10:00:00Z',
    expiryTtl: 0,
    expiryTtlString: '',
    ...extra,
  }
}

describe('zones/records — transporte', () => {
  it('getRecords does NOT paginate: it asks with listZone=true and no page parameters', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(
      env({ zone: { name: 'casa.test' }, records: [] }),
    )
    await getRecords('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('zones/records/get')
    expect(spy.mock.calls[0][1]?.body).toEqual({
      domain: 'casa.test',
      zone: 'casa.test',
      listZone: 'true',
      node: '',
    })
    expect(spy.mock.calls[0][1]?.body).not.toHaveProperty('pageNumber')
  })

  it('it returns null if the call fails', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await getRecords('t', 'x')).toBeNull()
  })

  it('add and delete are POST and carry `node` in the QUERY, not in the body', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await addRecord('t', { zone: 'casa.test' })
    expect(spy.mock.calls[0][0]).toBe('zones/records/add?node=')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(spy.mock.calls[0][1]?.body).not.toHaveProperty('node')

    await deleteRecord('t', { zone: 'casa.test' }, 'nodo-2')
    expect(spy.mock.calls[1][0]).toBe('zones/records/delete?node=nodo-2')
  })
})

describe('identity of a record', () => {
  it('A sends the IP and the SVCB hints flag', () => {
    expect(recordIdentity(reg('A', { ipAddress: '10.0.0.1' }), { updateSvcbHints: true })).toEqual({
      ipAddress: '10.0.0.1',
      updateSvcbHints: 'true',
    })
  })

  it('NS carries the glue when disabling and NOT when deleting', () => {
    const r = reg('NS', { nameServer: 'ns1.casa.test' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] })
    expect(recordIdentity(r)).toEqual({
      nameServer: 'ns1.casa.test',
      glue: '10.0.0.1, 10.0.0.2',
    })
    expect(recordIdentity(r, { forDeletion: true })).toEqual({ nameServer: 'ns1.casa.test' })
  })

  it('CNAME, DNAME and APP contribute nothing to the delete (zone.js:6420-6510)', () => {
    expect(recordIdentity(reg('CNAME', { cname: 'a.b' }), { forDeletion: true })).toEqual({})
    expect(recordIdentity(reg('DNAME', { dname: 'a.b' }), { forDeletion: true })).toEqual({})
    expect(
      recordIdentity(reg('APP', { appName: 'x', classPath: 'y', data: 'z' }), {
        forDeletion: true,
      }),
    ).toEqual({})
  })

  it('TXT identifies by the base64 strings, comma-joined', () => {
    const r = reg('TXT', { text: 'a b', characterStringsBase64: ['YQ==', 'Yg=='] })
    expect(recordIdentity(r)).toEqual({ characterStringsBase64: 'YQ==,Yg==' })
  })

  it('SVCB flattens svcParams and turns an empty target into the root', () => {
    const r = reg('SVCB', {
      svcPriority: 1,
      svcTargetName: '',
      svcParams: { alpn: 'h2', port: '443' },
      autoIpv4Hint: true,
      autoIpv6Hint: false,
    })
    expect(recordIdentity(r)).toEqual({
      svcPriority: '1',
      svcTargetName: '.',
      svcParams: 'alpn|h2|port|443',
      autoIpv4Hint: 'true',
      autoIpv6Hint: 'false',
    })
  })

  it('an empty svcParams travels as the string \"false\", not as an empty string', () => {
    expect(aplanarSvcParams({})).toBe('false')
    expect(aplanarSvcParams(undefined)).toBe('false')
  })

  it('with no glue, `glue` is an empty string', () => {
    expect(aplanarGlue(undefined)).toBe('')
  })

  it('FWD only drags the proxy along when the type has one', () => {
    const noProxy = reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'DefaultProxy' })
    expect(recordIdentity(noProxy)).not.toHaveProperty('proxyAddress')

    const withProxy = reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: false, proxyType: 'Socks5', proxyAddress: '10.0.0.9', proxyPort: 1080, proxyUsername: 'u', proxyPassword: 'p' })
    expect(recordIdentity(withProxy)).toMatchObject({
      proxyAddress: '10.0.0.9',
      proxyPort: '1080',
      proxyUsername: 'u',
      proxyPassword: 'p',
    })
  })

  it('an unknown type sends `rdata` only if the record brings it', () => {
    expect(recordIdentity(reg('TYPE65280', { value: 'ABCD' }))).toEqual({ rdata: 'ABCD' })
    expect(recordIdentity(reg('TYPE65280', {}))).toEqual({})
  })
})

describe('cuerpos completos', () => {
  it('the delete sends zone, domain and type, and the root goes as a dot', () => {
    const r = reg('MX', { preference: 10, exchange: 'mail.casa.test' }, { name: '' })
    expect(cuerpoBorrado('casa.test', r)).toEqual({
      zone: 'casa.test',
      domain: '.',
      type: 'MX',
      preference: '10',
      exchange: 'mail.casa.test',
    })
  })

  it('disabling resends the whole record with disable=true', () => {
    const r = reg('MX', { preference: 10, exchange: 'mail.casa.test' }, { comments: 'nota', expiryTtl: 60 })
    expect(cuerpoCambioDeEstado('casa.test', r, true, false)).toEqual({
      zone: 'casa.test',
      domain: 'www',
      type: 'MX',
      ttl: '3600',
      disable: 'true',
      comments: 'nota',
      expiryTtl: '60',
      preference: '10',
      exchange: 'mail.casa.test',
    })
  })
})

describe('loose rules of upstream', () => {
  it('the full name: empty is @, @ is the zone, and the root closes with a dot', () => {
    expect(fullDomain('casa.test', '')).toBe('casa.test')
    expect(fullDomain('casa.test', '@')).toBe('casa.test')
    expect(fullDomain('casa.test', 'www')).toBe('www.casa.test')
    expect(fullDomain('.', 'www')).toBe('www.')
  })

  it('without the record list loaded, the SVCB hints are asked for anyway', () => {
    // zone.js:4690 — the default case is `true`, not `false`.
    expect(zoneHasSvcbAutoHint(null, true, false)).toBe(true)
  })

  it('it only asks for hints if some SVCB/HTTPS has the automatic one of that family', () => {
    const svcb = reg('SVCB', { autoIpv4Hint: true, autoIpv6Hint: false })
    expect(zoneHasSvcbAutoHint([svcb], true, false)).toBe(true)
    expect(zoneHasSvcbAutoHint([svcb], false, true)).toBe(false)
    expect(zoneHasSvcbAutoHint([reg('A', { ipAddress: '1.1.1.1' })], true, true)).toBe(false)
  })
})
