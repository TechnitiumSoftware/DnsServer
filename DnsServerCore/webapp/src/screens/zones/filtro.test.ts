import { describe, expect, it } from 'vitest'
import { compilarFiltroDeNombre, filtrar } from './filtro'
import type { ResourceRecord } from '../../api/registros'

function reg(name: string, type: string): ResourceRecord {
  return {
    name,
    type,
    ttl: 3600,
    ttlString: '1h',
    disabled: false,
    rData: {},
    dnssecStatus: 'Unknown',
    lastUsedOn: '0001-01-01T00:00:00',
    lastModified: '2026-08-26T10:00:00Z',
    expiryTtl: 0,
    expiryTtlString: '',
  }
}

const RECORDS = [
  reg('casa.test', 'SOA'),
  reg('casa.test', 'NS'),
  reg('www.casa.test', 'A'),
  reg('www.casa.test', 'AAAA'),
  reg('mail.casa.test', 'A'),
  reg('*.casa.test', 'A'),
  reg('a.b.casa.test', 'A'),
]

describe('name filter', () => {
  it('without a wildcard the comparison is EXACT, not \"contains\"', () => {
    expect(filtrar(RECORDS, { name: 'www', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    // `w` does not find `www`: without a wildcard no prefix counts.
    expect(filtrar(RECORDS, { name: 'w', tipo: '' }, 'casa.test')).toEqual([])
  })

  it('`@` is the apex of the zone', () => {
    expect(filtrar(RECORDS, { name: '@', tipo: '' }, 'casa.test').map((r) => r.type)).toEqual([
      'SOA',
      'NS',
    ])
  })

  it('`@` at the root is the empty name', () => {
    expect(compilarFiltroDeNombre('@', '.').dominio).toBe('')
  })

  it('`*` looks for the literal WILDCARD record, it does not list everything', () => {
    // The zone.js:3548 line that looks like a bug and is not.
    expect(filtrar(RECORDS, { name: '*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      '*.casa.test',
    ])
  })

  it('a wildcard in the middle does behave as a glob', () => {
    expect(filtrar(RECORDS, { name: 'w*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    expect(filtrar(RECORDS, { name: 'a.*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'a.b.casa.test',
    ])
  })

  it('`?` stands in for one character', () => {
    expect(filtrar(RECORDS, { name: 'ww?', tipo: '' }, 'casa.test')).toHaveLength(2)
  })

  it('what is typed is lowercased; the zone name is NOT', () => {
    // `filterName.toLowerCase()` yes, `zone` no (zone.js:3533). With the zone name
    // the server returns it makes no difference, but it is what the original does.
    expect(filtrar(RECORDS, { name: 'WWW', tipo: '' }, 'casa.test')).toHaveLength(2)
    expect(compilarFiltroDeNombre('WWW', 'CASA.TEST').dominio).toBe('www.CASA.TEST')
  })
})

describe('type filter', () => {
  it('it is exact and uppercased', () => {
    expect(filtrar(RECORDS, { name: '', tipo: 'a' }, 'casa.test')).toHaveLength(4)
    expect(filtrar(RECORDS, { name: '', tipo: 'AAAA' }, 'casa.test')).toHaveLength(1)
  })

  it('it combines with the name one', () => {
    expect(filtrar(RECORDS, { name: 'www', tipo: 'A' }, 'casa.test')).toHaveLength(1)
  })

  it('with no filters it returns the same list, without copying it', () => {
    expect(filtrar(RECORDS, { name: '', tipo: '' }, 'casa.test')).toBe(RECORDS)
  })
})
