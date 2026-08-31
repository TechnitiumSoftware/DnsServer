import { describe, expect, it } from 'vitest'
import type { RegistroDns } from '../../api/zonelists'
import { entradasRData, extras, fechaCorta, meta, ttlPartido } from './registro'

const CACHE_DNSKEY: RegistroDns = {
  name: '',
  type: 'DNSKEY',
  ttl: '2000 (33m20s)',
  rData: {
    flags: 'SecureEntryPoint, ZoneKey',
    protocol: 3,
    algorithm: 'RSASHA256',
    algorithmNumber: 8,
    publicKey: 'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4',
    computedKeyTag: 20326,
  },
  dnssecStatus: 'Secure',
  dnssecRecords: ['. 7405 IN RRSIG 48 8 0 …'],
  responseMetadata: {
    nameServer: '1.1.1.1',
    protocol: 'Udp',
    datagramSize: '1139 bytes',
    roundTripTime: '2.58 ms',
  },
  lastUsedOn: '2026-08-25T13:10:49.1717478Z',
}

const ALLOWED_NS: RegistroDns = {
  name: 'example.org',
  type: 'NS',
  ttl: 14400,
  ttlString: '4h',
  disabled: false,
  rData: { nameServer: 'ns1.casa.test' },
  dnssecStatus: 'Unknown',
  lastUsedOn: '0001-01-01T00:00:00',
  lastModified: '0001-01-01T00:00:00',
  expiryTtl: 0,
  expiryTtlString: '0s',
}

describe('ttlPartido', () => {
  /* In cache the server sends the TTL already composed as a STRING ("218
     (3m38s)"); in allowed and blocked it sends the number and `ttlString` apart. */
  it('parte la cadena de cache en número y forma humana', () => {
    expect(ttlPartido(CACHE_DNSKEY)).toEqual({ valor: '2000', humano: '33m20s' })
  })

  it('compone el par de allowed y blocked a partir de ttl y ttlString', () => {
    expect(ttlPartido(ALLOWED_NS)).toEqual({ valor: '14400', humano: '4h' })
  })

  it('un registro rancio de cache llega como «0 (0s)» y se respeta', () => {
    expect(ttlPartido({ ...CACHE_DNSKEY, ttl: '0 (0s)' })).toEqual({ valor: '0', humano: '0s' })
  })
})

describe('entradasRData', () => {
  it('no pierde ningún campo de rData', () => {
    const claves = entradasRData(CACHE_DNSKEY.rData).map((e) => e.clave)
    // 6 fields, but algorithmNumber merges into algorithm: 5 rows are left.
    expect(claves).toEqual(['Flags', 'Protocol', 'Algorithm', 'Public key', 'Key tag'])
  })

  it('funde `x` con `xNumber` en una sola línea, sin perder el número', () => {
    const alg = entradasRData(CACHE_DNSKEY.rData).find((e) => e.clave === 'Algorithm')
    expect(alg?.valor).toBe('RSASHA256 (8)')
  })

  it('funde `x` con `xString`, que es como llega el SOA de cache', () => {
    const e = entradasRData({ refresh: 900, refreshString: '15m' })
    expect(e).toEqual([{ clave: 'Refresh', valor: '900 (15m)', largo: false }])
  })

  it('funde `x` con `xIdn` mostrando el nombre Unicode y el ASCII detrás', () => {
    const e = entradasRData({ nameServer: 'xn--maana-pta.test', nameServerIdn: 'mañana.test' })
    expect(e[0].valor).toBe('mañana.test (xn--maana-pta.test)')
  })

  it('marca como largas las claves públicas para poder truncarlas', () => {
    const pk = entradasRData(CACHE_DNSKEY.rData).find((e) => e.clave === 'Public key')
    expect(pk?.largo).toBe(true)
    expect(entradasRData({ ipAddress: '10.0.0.1' })[0].largo).toBe(false)
  })

  it('humaniza cualquier clave que no conozca en vez de esconderla', () => {
    expect(entradasRData({ campoInventadoDelFuturo: 7 })[0].clave).toBe('Campo inventado del futuro')
  })
})

describe('meta', () => {
  it('pone en la línea gris los metadatos de respuesta de cache, enteros', () => {
    expect(meta(CACHE_DNSKEY)).toEqual([
      'via 1.1.1.1',
      'Udp',
      '1139 bytes',
      '2.58 ms',
      'used 2026-08-25 13:10',
    ])
  })

  it('en allowed y blocked dice el estado DNSSEC y que nunca se ha usado', () => {
    expect(meta(ALLOWED_NS)).toContain('DNSSEC Unknown')
    expect(meta(ALLOWED_NS)).toContain('never used')
    expect(meta(ALLOWED_NS)).toContain('no expiry')
  })

  it('un expiryTtl mayor que cero sí se cuenta', () => {
    expect(meta({ ...ALLOWED_NS, expiryTtl: 3600, expiryTtlString: '1h' })).toContain('expires in 1h')
  })

  it('un registro deshabilitado se dice', () => {
    expect(meta({ ...ALLOWED_NS, disabled: true })).toContain('disabled')
  })
})

describe('fechaCorta', () => {
  it('recorta a minutos sin cambiar de huso: el servidor manda UTC', () => {
    expect(fechaCorta('2026-08-25T13:10:49.1717478Z')).toBe('2026-08-25 13:10')
  })

  it('el año 0001 es «nunca», no una fecha', () => {
    expect(fechaCorta('0001-01-01T00:00:00')).toBeNull()
    expect(fechaCorta(undefined)).toBeNull()
  })
})

describe('extras', () => {
  it('saca a filas los campos que no son de rData ni de la línea gris', () => {
    const e = extras({ ...ALLOWED_NS, comments: 'una nota', eDnsClientSubnet: '10.0.0.0/24' })
    expect(e.map((x) => x.clave)).toContain('Comments')
    expect(e.map((x) => x.clave)).toContain('EDNS Client Subnet')
  })

  it('reparte la salud del servidor de nombres campo a campo', () => {
    const e = extras({
      ...CACHE_DNSKEY,
      nameServerMetadata: {
        totalQueries: 12,
        answerRate: '100%',
        smoothedRoundTripTime: '3 ms',
        smoothedPenaltyRoundTripTime: '3 ms',
        netRoundTripTime: '3 ms',
        isMisconfigured: false,
      },
    })
    expect(e.map((x) => x.clave)).toContain('Total queries')
    expect(e.map((x) => x.clave)).toContain('Answer rate')
  })

  /* The safety net: if the server adds a field tomorrow, it comes out anyway. */
  it('un campo desconocido del registro no se pierde', () => {
    const e = extras({ ...ALLOWED_NS, campoNuevo: 'valor' })
    expect(e).toContainEqual({ clave: 'Campo nuevo', valor: 'valor', largo: false })
  })

  it('los campos ya pintados en otro sitio no se repiten aquí', () => {
    const claves = extras(CACHE_DNSKEY).map((x) => x.clave)
    expect(claves).not.toContain('Rdata')
    expect(claves).not.toContain('Ttl')
    expect(claves).not.toContain('Response metadata')
    expect(claves).not.toContain('Dnssec records')
  })
})
