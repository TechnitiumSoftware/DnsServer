import { describe, expect, it } from 'vitest'
import type { ResourceRecord } from '../../api/records'
import {
  rowActions,
  recordCells,
  escaparTxt,
  nombreRelativo,
  ocultarDnssec,
  recordFooter,
} from './record-view'
import { zoneHeader, typesHiddenWhenAdding } from './zone-view'

function reg(type: string, rData: Record<string, unknown>, extra: Partial<ResourceRecord> = {}): ResourceRecord {
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
function pairs(r: ResourceRecord): Record<string, string> {
  const out: Record<string, string> = {}
  for (const c of recordCells(r)) {
    if (c.clase === 'pairs') for (const p of c.pairs) out[p.label] = p.value
  }
  return out
}

describe('the Data cell by type', () => {
  it('A and AAAA are just the address', () => {
    expect(recordCells(reg('A', { ipAddress: '10.0.0.1' }))).toEqual([
      { clase: 'value', text: '10.0.0.1' },
    ])
  })

  it('SOA composes value and readable string on four fields', () => {
    const p = pairs(
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
    const p = pairs(reg('DS', { keyTag: 1, algorithm: 'ECDSAP256SHA256', algorithmNumber: 13, digestType: 'SHA256', digestTypeNumber: '2', digest: 'AB' }))
    expect(p['Algorithm:']).toBe('ECDSAP256SHA256 (13)')
    expect(p['Digest Type:']).toBe('SHA256 (2)')
  })

  it('NS shows the glue only if it brings it', () => {
    expect(pairs(reg('NS', { nameServer: 'ns1' }))).not.toHaveProperty('Glue Addresses:')
    const withGlue = pairs(reg('NS', { nameServer: 'ns1' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] }))
    expect(withGlue['Glue Addresses:']).toBe('10.0.0.1, 10.0.0.2')
  })

  it('a split TXT shows each string in quotes and on its own line', () => {
    const cells = recordCells(
      reg('TXT', { splitText: true, characterStrings: ['uno', 'dos'], text: 'uno dos' }),
    )
    expect(cells[0]).toEqual({ clase: 'lines', lines: ['"uno"', '"dos"'] })
  })

  it('escapes backslashes, carriage returns, newlines and quotes of a TXT', () => {
    expect(escaparTxt('a\\b"c\nd')).toBe('a\\\\b\\"c\\nd')
  })

  it('SVCB states the mode according to the priority', () => {
    expect(pairs(reg('SVCB', { svcPriority: 0, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '0 (alias mode)',
    )
    expect(pairs(reg('SVCB', { svcPriority: 1, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '1 (service mode)',
    )
  })

  it('SVCB hides the hints whose value the server sets', () => {
    const cells = recordCells(
      reg('SVCB', {
        svcPriority: 1,
        svcTargetName: 'x',
        svcParams: { alpn: 'h2', ipv4hint: '10.0.0.1', ipv6hint: '::1' },
        autoIpv4Hint: true,
        autoIpv6Hint: false,
      }),
    )
    const table = cells.find((c) => c.clase === 'table')
    expect(table).toBeDefined()
    const keys = table!.clase === 'table' ? table!.rows.map((f) => f[0]) : []
    expect(keys).toEqual(['alpn', 'ipv6hint'])
  })

  it('a DNSKEY with no state does not show the \"Key State\" row', () => {
    expect(pairs(reg('DNSKEY', { flags: 257, protocol: 3, algorithm: 'X', algorithmNumber: 13, publicKey: 'AA', computedKeyTag: 1 }))).not.toHaveProperty(
      'Key State:',
    )
  })

  it('FWD only shows the proxy when the type has one', () => {
    const sin = pairs(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'DefaultProxy' }))
    expect(sin).not.toHaveProperty('Proxy Address:')
    const con = pairs(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'Socks5', proxyAddress: '10.0.0.9', proxyPort: 1080 }))
    expect(con['Proxy Address:']).toBe('10.0.0.9')
  })

  it('an unknown type shows its RDATA', () => {
    expect(pairs(reg('TYPE65280', { value: 'ABCD' }))['RDATA:']).toBe('ABCD')
  })
})

describe('the footer of the cell', () => {
  const AHORA = Date.parse('2026-08-26T10:04:00Z')

  it('\"never\" carries no age after it', () => {
    const p = recordFooter(reg('A', {}), AHORA)
    expect(p.find((x) => x.label === 'Last Used:')?.value).toContain('(never)')
  })

  it('the last modification does carry it', () => {
    const p = recordFooter(reg('A', {}), AHORA)
    expect(p.find((x) => x.label === 'Last Modified:')?.value).toContain('4 minutes ago')
  })

  it('a minimum modification date is NOT shown', () => {
    const p = recordFooter(reg('A', {}, { lastModified: '0001-01-01T00:00:00' }), AHORA)
    expect(p.find((x) => x.label === 'Last Modified:')).toBeUndefined()
  })

  it('the expiry only appears with expiryTtl > 0', () => {
    expect(recordFooter(reg('A', {}), AHORA).find((x) => x.label === 'Expiry TTL:')).toBeUndefined()
    const con = recordFooter(reg('A', {}, { expiryTtl: 3600, expiryTtlString: '1h' }), AHORA)
    expect(con.find((x) => x.label === 'Expiry TTL:')?.value).toBe('3600 (1h)')
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
      expect(rowActions(t, 'A').ocultas).toBe(true)
    }
  })

  it('on a Catalog only the SOA can be edited; the rest offer nothing', () => {
    expect(rowActions('Catalog', 'SOA')).toEqual({ ocultas: false, editingOnly: true })
    expect(rowActions('Catalog', 'A').ocultas).toBe(true)
  })

  it('on a Primary the SOA is edited but neither deleted nor disabled', () => {
    expect(rowActions('Primary', 'SOA')).toEqual({ ocultas: false, editingOnly: true })
  })

  it('the six records DNSSEC generates offer no buttons', () => {
    for (const t of ['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD']) {
      expect(rowActions('Primary', t).ocultas).toBe(true)
    }
  })

  it('an ordinary record offers them all', () => {
    expect(rowActions('Primary', 'A')).toEqual({ ocultas: false, editingOnly: false })
  })
})

describe('hiding the DNSSEC records', () => {
  it('removes the five types, not six', () => {
    const list = ['A', 'RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].map((t) =>
      reg(t, {}),
    )
    // ZONEMD is not in the `zoneHideDnssecRecords` list although it is in the
    // no-actions records one. They are two different lists in upstream.
    expect(ocultarDnssec(list).map((r) => r.type)).toEqual(['A', 'ZONEMD'])
  })
})

describe('the header of an open zone', () => {
  it('an unsigned Primary offers signing and nothing else of DNSSEC', () => {
    const c = zoneHeader('Primary', 'Unsigned')
    expect(c.dnssec).toBe(true)
    expect(c.sign).toBe(true)
    expect(c.unsign).toBe(false)
    expect(c.verDs).toBe(false)
  })

  it('a signed Primary offers everything except signing', () => {
    const c = zoneHeader('Primary', 'SignedWithNSEC')
    expect(c.sign).toBe(false)
    expect(c.unsign).toBe(true)
    expect(c.verDs).toBe(true)
    expect(c.propiedades).toBe(true)
  })

  it('a signed Secondary shows the menu but ONLY to hide records', () => {
    const c = zoneHeader('Secondary', 'SignedWithNSEC3')
    expect(c.dnssec).toBe(true)
    expect(c.toggleDnssecRecords).toBe(true)
    expect(c.sign).toBe(false)
    expect(c.verDs).toBe(false)
    expect(c.propiedades).toBe(false)
  })

  it('an unsigned Secondary does not show the DNSSEC menu', () => {
    expect(zoneHeader('Secondary', 'Unsigned').dnssec).toBe(false)
  })

  it('only Primary and Forwarder allow adding records by hand', () => {
    expect(zoneHeader('Primary', 'Unsigned').addRecord).toBe(true)
    expect(zoneHeader('Forwarder', 'Unsigned').addRecord).toBe(true)
    expect(zoneHeader('Secondary', 'Unsigned').addRecord).toBe(false)
    expect(zoneHeader('Catalog', 'Unsigned').addRecord).toBe(false)
  })

  it('exporting covers more types than importing', () => {
    expect(zoneHeader('Secondary', 'Unsigned').runExport).toBe(true)
    expect(zoneHeader('Secondary', 'Unsigned').runImport).toBe(false)
  })
})

describe('which types \"Add Record\" offers', () => {
  it('a Forwarder hides the three DNSSEC ones', () => {
    expect(typesHiddenWhenAdding('Forwarder', 'Unsigned')).toEqual(['DS', 'SSHFP', 'TLSA'])
  })

  it('an unsigned Primary hides FWD and the three DNSSEC ones', () => {
    expect(typesHiddenWhenAdding('Primary', 'Unsigned')).toEqual(['FWD', 'DS', 'SSHFP', 'TLSA'])
  })

  it('a SIGNED Primary changes what it hides: DS/SSHFP/TLSA appear and ANAME and APP go', () => {
    expect(typesHiddenWhenAdding('Primary', 'SignedWithNSEC')).toEqual(['FWD', 'ANAME', 'APP'])
  })
})
