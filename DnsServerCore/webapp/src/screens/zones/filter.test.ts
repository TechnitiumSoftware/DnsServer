import { describe, expect, it } from 'vitest'
import { compilarFiltroDeNombre, filterBy } from './filter'
import type { ResourceRecord } from '../../api/records'

function rec(name: string, type: string): ResourceRecord {
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
  rec('casa.test', 'SOA'),
  rec('casa.test', 'NS'),
  rec('www.casa.test', 'A'),
  rec('www.casa.test', 'AAAA'),
  rec('mail.casa.test', 'A'),
  rec('*.casa.test', 'A'),
  rec('a.b.casa.test', 'A'),
]

describe('name filter', () => {
  it('without a wildcard the comparison is EXACT, not \"contains\"', () => {
    expect(filterBy(RECORDS, { name: 'www', type: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    // `w` does not find `www`: without a wildcard no prefix counts.
    expect(filterBy(RECORDS, { name: 'w', type: '' }, 'casa.test')).toEqual([])
  })

  it('`@` is the apex of the zone', () => {
    expect(filterBy(RECORDS, { name: '@', type: '' }, 'casa.test').map((r) => r.type)).toEqual([
      'SOA',
      'NS',
    ])
  })

  it('`@` at the root is the empty name', () => {
    expect(compilarFiltroDeNombre('@', '.').domain).toBe('')
  })

  it('`*` looks for the literal WILDCARD record, it does not list everything', () => {
    // The zone.js:3548 line that looks like a bug and is not.
    expect(filterBy(RECORDS, { name: '*', type: '' }, 'casa.test').map((r) => r.name)).toEqual([
      '*.casa.test',
    ])
  })

  it('a wildcard in the middle does behave as a glob', () => {
    expect(filterBy(RECORDS, { name: 'w*', type: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    expect(filterBy(RECORDS, { name: 'a.*', type: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'a.b.casa.test',
    ])
  })

  it('`?` stands in for one character', () => {
    expect(filterBy(RECORDS, { name: 'ww?', type: '' }, 'casa.test')).toHaveLength(2)
  })

  it('what is typed is lowercased; the zone name is NOT', () => {
    // `filterName.toLowerCase()` yes, `zone` no (zone.js:3533). With the zone name
    // the server returns it makes no difference, but it is what the original does.
    expect(filterBy(RECORDS, { name: 'WWW', type: '' }, 'casa.test')).toHaveLength(2)
    expect(compilarFiltroDeNombre('WWW', 'CASA.TEST').domain).toBe('www.CASA.TEST')
  })
})

describe('type filter', () => {
  it('it is exact and uppercased', () => {
    expect(filterBy(RECORDS, { name: '', type: 'a' }, 'casa.test')).toHaveLength(4)
    expect(filterBy(RECORDS, { name: '', type: 'AAAA' }, 'casa.test')).toHaveLength(1)
  })

  it('it combines with the name one', () => {
    expect(filterBy(RECORDS, { name: 'www', type: 'A' }, 'casa.test')).toHaveLength(1)
  })

  it('with no filters it returns the same list, without copying it', () => {
    expect(filterBy(RECORDS, { name: '', type: '' }, 'casa.test')).toBe(RECORDS)
  })
})
