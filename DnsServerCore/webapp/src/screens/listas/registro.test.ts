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
  it('it splits the cache string into a number and a human form', () => {
    expect(ttlPartido(CACHE_DNSKEY)).toEqual({ value: '2000', humano: '33m20s' })
  })

  it('it composes the allowed and blocked pair out of ttl and ttlString', () => {
    expect(ttlPartido(ALLOWED_NS)).toEqual({ value: '14400', humano: '4h' })
  })

  it('a stale cache record arrives as \"0 (0s)\" and is respected', () => {
    expect(ttlPartido({ ...CACHE_DNSKEY, ttl: '0 (0s)' })).toEqual({ value: '0', humano: '0s' })
  })
})

describe('entradasRData', () => {
  it('it loses no rData field', () => {
    const keys = entradasRData(CACHE_DNSKEY.rData).map((e) => e.key)
    // 6 fields, but algorithmNumber merges into algorithm: 5 rows are left.
    expect(keys).toEqual(['Flags', 'Protocol', 'Algorithm', 'Public key', 'Key tag'])
  })

  it('it merges `x` with `xNumber` on a single line, without losing the number', () => {
    const alg = entradasRData(CACHE_DNSKEY.rData).find((e) => e.key === 'Algorithm')
    expect(alg?.value).toBe('RSASHA256 (8)')
  })

  it('it merges `x` with `xString`, which is how the cache SOA arrives', () => {
    const e = entradasRData({ refresh: 900, refreshString: '15m' })
    expect(e).toEqual([{ key: 'Refresh', value: '900 (15m)', long: false }])
  })

  it('it merges `x` with `xIdn` showing the Unicode name and the ASCII after it', () => {
    const e = entradasRData({ nameServer: 'xn--maana-pta.test', nameServerIdn: 'mañana.test' })
    expect(e[0].value).toBe('mañana.test (xn--maana-pta.test)')
  })

  it('it marks the public keys as long so they can be truncated', () => {
    const pk = entradasRData(CACHE_DNSKEY.rData).find((e) => e.key === 'Public key')
    expect(pk?.long).toBe(true)
    expect(entradasRData({ ipAddress: '10.0.0.1' })[0].long).toBe(false)
  })

  it('it humanises any key it does not know instead of hiding it', () => {
    expect(entradasRData({ campoInventadoDelFuturo: 7 })[0].key).toBe('Campo inventado del futuro')
  })
})

describe('meta', () => {
  it('it puts the cache response metadata on the grey line, in full', () => {
    expect(meta(CACHE_DNSKEY)).toEqual([
      'via 1.1.1.1',
      'Udp',
      '1139 bytes',
      '2.58 ms',
      'used 2026-08-25 13:10',
    ])
  })

  it('in allowed and blocked it states the DNSSEC state and that it was never used', () => {
    expect(meta(ALLOWED_NS)).toContain('DNSSEC Unknown')
    expect(meta(ALLOWED_NS)).toContain('never used')
    expect(meta(ALLOWED_NS)).toContain('no expiry')
  })

  it('an expiryTtl greater than zero does count', () => {
    expect(meta({ ...ALLOWED_NS, expiryTtl: 3600, expiryTtlString: '1h' })).toContain('expires in 1h')
  })

  it('a disabled record is stated', () => {
    expect(meta({ ...ALLOWED_NS, disabled: true })).toContain('disabled')
  })
})

describe('fechaCorta', () => {
  it('it trims to minutes without changing time zone: the server sends UTC', () => {
    expect(fechaCorta('2026-08-25T13:10:49.1717478Z')).toBe('2026-08-25 13:10')
  })

  it('year 0001 is \"never\", not a date', () => {
    expect(fechaCorta('0001-01-01T00:00:00')).toBeNull()
    expect(fechaCorta(undefined)).toBeNull()
  })
})

describe('extras', () => {
  it('it pulls into rows the fields that belong neither to rData nor to the grey line', () => {
    const e = extras({ ...ALLOWED_NS, comments: 'una nota', eDnsClientSubnet: '10.0.0.0/24' })
    expect(e.map((x) => x.key)).toContain('Comments')
    expect(e.map((x) => x.key)).toContain('EDNS Client Subnet')
  })

  it('it spreads the name server health out field by field', () => {
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
    expect(e.map((x) => x.key)).toContain('Total queries')
    expect(e.map((x) => x.key)).toContain('Answer rate')
  })

  /* The safety net: if the server adds a field tomorrow, it comes out anyway. */
  it('an unknown field of the record is not lost', () => {
    const e = extras({ ...ALLOWED_NS, campoNuevo: 'value' })
    expect(e).toContainEqual({ key: 'Campo nuevo', value: 'value', long: false })
  })

  it('the fields already drawn elsewhere are not repeated here', () => {
    const keys = extras(CACHE_DNSKEY).map((x) => x.key)
    expect(keys).not.toContain('Rdata')
    expect(keys).not.toContain('Ttl')
    expect(keys).not.toContain('Response metadata')
    expect(keys).not.toContain('Dnssec records')
  })
})
