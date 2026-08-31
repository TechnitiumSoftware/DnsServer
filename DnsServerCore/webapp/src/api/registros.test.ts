import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  getRecords,
  addRecord,
  deleteRecord,
  identidadRegistro,
  aplanarSvcParams,
  aplanarGlue,
  cuerpoBorrado,
  cuerpoCambioDeEstado,
  dominioCompleto,
  zonaTienePistaSvcbAuto,
  type Registro,
} from './registros'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())
const env = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

/** A record with the bare minimum, so as not to repeat twelve fields in each case. */
function reg(type: string, rData: Record<string, unknown>, extra: Partial<Registro> = {}): Registro {
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
  it('getRecords NO pagina: pide listZone=true y sin parámetros de página', async () => {
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

  it('devuelve null si la llamada falla', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await getRecords('t', 'x')).toBeNull()
  })

  it('add y delete son POST y llevan `node` en la QUERY, no en el cuerpo', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await addRecord('t', { zone: 'casa.test' })
    expect(spy.mock.calls[0][0]).toBe('zones/records/add?node=')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(spy.mock.calls[0][1]?.body).not.toHaveProperty('node')

    await deleteRecord('t', { zone: 'casa.test' }, 'nodo-2')
    expect(spy.mock.calls[1][0]).toBe('zones/records/delete?node=nodo-2')
  })
})

describe('identidad de un registro', () => {
  it('A manda la IP y la bandera de pistas SVCB', () => {
    expect(identidadRegistro(reg('A', { ipAddress: '10.0.0.1' }), { updateSvcbHints: true })).toEqual({
      ipAddress: '10.0.0.1',
      updateSvcbHints: 'true',
    })
  })

  it('NS lleva el pegamento al deshabilitar y NO al borrar', () => {
    const r = reg('NS', { nameServer: 'ns1.casa.test' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] })
    expect(identidadRegistro(r)).toEqual({
      nameServer: 'ns1.casa.test',
      glue: '10.0.0.1, 10.0.0.2',
    })
    expect(identidadRegistro(r, { paraBorrado: true })).toEqual({ nameServer: 'ns1.casa.test' })
  })

  it('CNAME, DNAME y APP no aportan nada al borrado (zone.js:6420-6510)', () => {
    expect(identidadRegistro(reg('CNAME', { cname: 'a.b' }), { paraBorrado: true })).toEqual({})
    expect(identidadRegistro(reg('DNAME', { dname: 'a.b' }), { paraBorrado: true })).toEqual({})
    expect(
      identidadRegistro(reg('APP', { appName: 'x', classPath: 'y', data: 'z' }), {
        paraBorrado: true,
      }),
    ).toEqual({})
  })

  it('TXT identifica por las cadenas en base64, unidas por coma', () => {
    const r = reg('TXT', { text: 'a b', characterStringsBase64: ['YQ==', 'Yg=='] })
    expect(identidadRegistro(r)).toEqual({ characterStringsBase64: 'YQ==,Yg==' })
  })

  it('SVCB aplana svcParams y convierte un target vacío en la raíz', () => {
    const r = reg('SVCB', {
      svcPriority: 1,
      svcTargetName: '',
      svcParams: { alpn: 'h2', port: '443' },
      autoIpv4Hint: true,
      autoIpv6Hint: false,
    })
    expect(identidadRegistro(r)).toEqual({
      svcPriority: '1',
      svcTargetName: '.',
      svcParams: 'alpn|h2|port|443',
      autoIpv4Hint: 'true',
      autoIpv6Hint: 'false',
    })
  })

  it('svcParams vacío viaja como la cadena «false», no como cadena vacía', () => {
    expect(aplanarSvcParams({})).toBe('false')
    expect(aplanarSvcParams(undefined)).toBe('false')
  })

  it('sin pegamento, `glue` es cadena vacía', () => {
    expect(aplanarGlue(undefined)).toBe('')
  })

  it('FWD sólo arrastra el proxy cuando el tipo lo tiene', () => {
    const sinProxy = reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'DefaultProxy' })
    expect(identidadRegistro(sinProxy)).not.toHaveProperty('proxyAddress')

    const conProxy = reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: false, proxyType: 'Socks5', proxyAddress: '10.0.0.9', proxyPort: 1080, proxyUsername: 'u', proxyPassword: 'p' })
    expect(identidadRegistro(conProxy)).toMatchObject({
      proxyAddress: '10.0.0.9',
      proxyPort: '1080',
      proxyUsername: 'u',
      proxyPassword: 'p',
    })
  })

  it('un tipo desconocido manda `rdata` sólo si el registro lo trae', () => {
    expect(identidadRegistro(reg('TYPE65280', { value: 'ABCD' }))).toEqual({ rdata: 'ABCD' })
    expect(identidadRegistro(reg('TYPE65280', {}))).toEqual({})
  })
})

describe('cuerpos completos', () => {
  it('el borrado manda zone, domain y type, y la raíz va como punto', () => {
    const r = reg('MX', { preference: 10, exchange: 'mail.casa.test' }, { name: '' })
    expect(cuerpoBorrado('casa.test', r)).toEqual({
      zone: 'casa.test',
      domain: '.',
      type: 'MX',
      preference: '10',
      exchange: 'mail.casa.test',
    })
  })

  it('deshabilitar reenvía el registro entero con disable=true', () => {
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

describe('reglas sueltas de upstream', () => {
  it('el nombre completo: vacío es @, @ es la zona, y la raíz cierra con punto', () => {
    expect(dominioCompleto('casa.test', '')).toBe('casa.test')
    expect(dominioCompleto('casa.test', '@')).toBe('casa.test')
    expect(dominioCompleto('casa.test', 'www')).toBe('www.casa.test')
    expect(dominioCompleto('.', 'www')).toBe('www.')
  })

  it('sin la lista de registros cargada, las pistas SVCB se piden igual', () => {
    // zone.js:4690 — the default case is `true`, not `false`.
    expect(zonaTienePistaSvcbAuto(null, true, false)).toBe(true)
  })

  it('sólo pide pistas si algún SVCB/HTTPS tiene la automática de esa familia', () => {
    const svcb = reg('SVCB', { autoIpv4Hint: true, autoIpv6Hint: false })
    expect(zonaTienePistaSvcbAuto([svcb], true, false)).toBe(true)
    expect(zonaTienePistaSvcbAuto([svcb], false, true)).toBe(false)
    expect(zonaTienePistaSvcbAuto([reg('A', { ipAddress: '1.1.1.1' })], true, true)).toBe(false)
  })
})
