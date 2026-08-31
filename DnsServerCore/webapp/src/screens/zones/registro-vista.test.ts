import { describe, expect, it } from 'vitest'
import type { Registro } from '../../api/registros'
import {
  accionesDeFila,
  celdasDeRegistro,
  escaparTxt,
  nombreRelativo,
  ocultarDnssec,
  pieDeRegistro,
} from './registro-vista'
import { cabeceraDeZona, tiposOcultosAlAnadir } from './vista-zona'

function reg(type: string, rData: Record<string, unknown>, extra: Partial<Registro> = {}): Registro {
  return {
    name: 'www.casa.test',
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

/** Flattens the cells into pairs so they can be asserted on without mounting. */
function pares(r: Registro): Record<string, string> {
  const out: Record<string, string> = {}
  for (const c of celdasDeRegistro(r)) {
    if (c.clase === 'pares') for (const p of c.pares) out[p.etiqueta] = p.valor
  }
  return out
}

describe('the Data cell by type', () => {
  it('A and AAAA are just the address', () => {
    expect(celdasDeRegistro(reg('A', { ipAddress: '10.0.0.1' }))).toEqual([
      { clase: 'valor', texto: '10.0.0.1' },
    ])
  })

  it('SOA composes value and readable string on four fields', () => {
    const p = pares(
      reg('SOA', {
        primaryNameServer: 'ns1',
        responsiblePerson: 'a@b',
        serial: 7,
        refresh: 900, refreshString: '15m',
        retry: 300, retryString: '5m',
        expire: 604800, expireString: '1w',
        minimum: 900, minimumString: '15m',
        useSerialDateScheme: false,
      }),
    )
    expect(p['Refresh:']).toBe('900 (15m)')
    expect(p['Expire:']).toBe('604800 (1w)')
    expect(p['Use Serial Date Scheme:']).toBe('false')
  })

  it('DS and RRSIG compose \"algorithm (number)\"', () => {
    const p = pares(reg('DS', { keyTag: 1, algorithm: 'ECDSAP256SHA256', algorithmNumber: 13, digestType: 'SHA256', digestTypeNumber: '2', digest: 'AB' }))
    expect(p['Algorithm:']).toBe('ECDSAP256SHA256 (13)')
    expect(p['Digest Type:']).toBe('SHA256 (2)')
  })

  it('NS shows the glue only if it brings it', () => {
    expect(pares(reg('NS', { nameServer: 'ns1' }))).not.toHaveProperty('Glue Addresses:')
    const conGlue = pares(reg('NS', { nameServer: 'ns1' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] }))
    expect(conGlue['Glue Addresses:']).toBe('10.0.0.1, 10.0.0.2')
  })

  it('a split TXT shows each string in quotes and on its own line', () => {
    const celdas = celdasDeRegistro(
      reg('TXT', { splitText: true, characterStrings: ['uno', 'dos'], text: 'uno dos' }),
    )
    expect(celdas[0]).toEqual({ clase: 'lineas', lineas: ['"uno"', '"dos"'] })
  })

  it('escapes backslashes, carriage returns, newlines and quotes of a TXT', () => {
    expect(escaparTxt('a\\b"c\nd')).toBe('a\\\\b\\"c\\nd')
  })

  it('SVCB states the mode according to the priority', () => {
    expect(pares(reg('SVCB', { svcPriority: 0, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '0 (alias mode)',
    )
    expect(pares(reg('SVCB', { svcPriority: 1, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '1 (service mode)',
    )
  })

  it('SVCB hides the hints whose value the server sets', () => {
    const celdas = celdasDeRegistro(
      reg('SVCB', {
        svcPriority: 1,
        svcTargetName: 'x',
        svcParams: { alpn: 'h2', ipv4hint: '10.0.0.1', ipv6hint: '::1' },
        autoIpv4Hint: true,
        autoIpv6Hint: false,
      }),
    )
    const tabla = celdas.find((c) => c.clase === 'tabla')
    expect(tabla).toBeDefined()
    const claves = tabla!.clase === 'tabla' ? tabla!.filas.map((f) => f[0]) : []
    expect(claves).toEqual(['alpn', 'ipv6hint'])
  })

  it('a DNSKEY with no state does not show the \"Key State\" row', () => {
    expect(pares(reg('DNSKEY', { flags: 257, protocol: 3, algorithm: 'X', algorithmNumber: 13, publicKey: 'AA', computedKeyTag: 1 }))).not.toHaveProperty(
      'Key State:',
    )
  })

  it('FWD only shows the proxy when the type has one', () => {
    const sin = pares(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'DefaultProxy' }))
    expect(sin).not.toHaveProperty('Proxy Address:')
    const con = pares(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'Socks5', proxyAddress: '10.0.0.9', proxyPort: 1080 }))
    expect(con['Proxy Address:']).toBe('10.0.0.9')
  })

  it('an unknown type shows its RDATA', () => {
    expect(pares(reg('TYPE65280', { value: 'ABCD' }))['RDATA:']).toBe('ABCD')
  })
})

describe('the footer of the cell', () => {
  const AHORA = Date.parse('2026-08-26T10:04:00Z')

  it('\"never\" carries no age after it', () => {
    const p = pieDeRegistro(reg('A', {}), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Used:')?.valor).toContain('(never)')
  })

  it('the last modification does carry it', () => {
    const p = pieDeRegistro(reg('A', {}), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Modified:')?.valor).toContain('4 minutes ago')
  })

  it('a minimum modification date is NOT shown', () => {
    const p = pieDeRegistro(reg('A', {}, { lastModified: '0001-01-01T00:00:00' }), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Modified:')).toBeUndefined()
  })

  it('the expiry only appears with expiryTtl > 0', () => {
    expect(pieDeRegistro(reg('A', {}), AHORA).find((x) => x.etiqueta === 'Expiry TTL:')).toBeUndefined()
    const con = pieDeRegistro(reg('A', {}, { expiryTtl: 3600, expiryTtlString: '1h' }), AHORA)
    expect(con.find((x) => x.etiqueta === 'Expiry TTL:')?.valor).toBe('3600 (1h)')
  })
})

describe('the name relative to the zone', () => {
  it('the apex is @', () => {
    expect(nombreRelativo('casa.test', 'casa.test')).toBe('@')
  })
  it('a sub-domain loses the suffix', () => {
    expect(nombreRelativo('www.casa.test', 'casa.test')).toBe('www')
    expect(nombreRelativo('a.b.casa.test', 'casa.test')).toBe('a.b')
  })
  it('the empty name is the root', () => {
    expect(nombreRelativo('', '.')).toBe('@')
  })
})

describe('which buttons a row offers', () => {
  it('on a secondary there are none', () => {
    for (const t of ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']) {
      expect(accionesDeFila(t, 'A').ocultas).toBe(true)
    }
  })

  it('on a Catalog only the SOA can be edited; the rest offer nothing', () => {
    expect(accionesDeFila('Catalog', 'SOA')).toEqual({ ocultas: false, soloEdicion: true })
    expect(accionesDeFila('Catalog', 'A').ocultas).toBe(true)
  })

  it('on a Primary the SOA is edited but neither deleted nor disabled', () => {
    expect(accionesDeFila('Primary', 'SOA')).toEqual({ ocultas: false, soloEdicion: true })
  })

  it('the six records DNSSEC generates offer no buttons', () => {
    for (const t of ['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD']) {
      expect(accionesDeFila('Primary', t).ocultas).toBe(true)
    }
  })

  it('an ordinary record offers them all', () => {
    expect(accionesDeFila('Primary', 'A')).toEqual({ ocultas: false, soloEdicion: false })
  })
})

describe('hiding the DNSSEC records', () => {
  it('removes the five types, not six', () => {
    const lista = ['A', 'RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].map((t) =>
      reg(t, {}),
    )
    // ZONEMD is not in the `zoneHideDnssecRecords` list although it is in the
    // no-actions records one. They are two different lists in upstream.
    expect(ocultarDnssec(lista).map((r) => r.type)).toEqual(['A', 'ZONEMD'])
  })
})

describe('the header of an open zone', () => {
  it('an unsigned Primary offers signing and nothing else of DNSSEC', () => {
    const c = cabeceraDeZona('Primary', 'Unsigned')
    expect(c.dnssec).toBe(true)
    expect(c.firmar).toBe(true)
    expect(c.desfirmar).toBe(false)
    expect(c.verDs).toBe(false)
  })

  it('a signed Primary offers everything except signing', () => {
    const c = cabeceraDeZona('Primary', 'SignedWithNSEC')
    expect(c.firmar).toBe(false)
    expect(c.desfirmar).toBe(true)
    expect(c.verDs).toBe(true)
    expect(c.propiedades).toBe(true)
  })

  it('a signed Secondary shows the menu but ONLY to hide records', () => {
    const c = cabeceraDeZona('Secondary', 'SignedWithNSEC3')
    expect(c.dnssec).toBe(true)
    expect(c.alternarRegistrosDnssec).toBe(true)
    expect(c.firmar).toBe(false)
    expect(c.verDs).toBe(false)
    expect(c.propiedades).toBe(false)
  })

  it('an unsigned Secondary does not show the DNSSEC menu', () => {
    expect(cabeceraDeZona('Secondary', 'Unsigned').dnssec).toBe(false)
  })

  it('only Primary and Forwarder allow adding records by hand', () => {
    expect(cabeceraDeZona('Primary', 'Unsigned').anadirRegistro).toBe(true)
    expect(cabeceraDeZona('Forwarder', 'Unsigned').anadirRegistro).toBe(true)
    expect(cabeceraDeZona('Secondary', 'Unsigned').anadirRegistro).toBe(false)
    expect(cabeceraDeZona('Catalog', 'Unsigned').anadirRegistro).toBe(false)
  })

  it('exporting covers more types than importing', () => {
    expect(cabeceraDeZona('Secondary', 'Unsigned').exportar).toBe(true)
    expect(cabeceraDeZona('Secondary', 'Unsigned').importar).toBe(false)
  })
})

describe('which types \"Add Record\" offers', () => {
  it('a Forwarder hides the three DNSSEC ones', () => {
    expect(tiposOcultosAlAnadir('Forwarder', 'Unsigned')).toEqual(['DS', 'SSHFP', 'TLSA'])
  })

  it('an unsigned Primary hides FWD and the three DNSSEC ones', () => {
    expect(tiposOcultosAlAnadir('Primary', 'Unsigned')).toEqual(['FWD', 'DS', 'SSHFP', 'TLSA'])
  })

  it('a SIGNED Primary changes what it hides: DS/SSHFP/TLSA appear and ANAME and APP go', () => {
    expect(tiposOcultosAlAnadir('Primary', 'SignedWithNSEC')).toEqual(['FWD', 'ANAME', 'APP'])
  })
})
