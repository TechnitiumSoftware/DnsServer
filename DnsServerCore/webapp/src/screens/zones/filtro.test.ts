import { describe, expect, it } from 'vitest'
import { compilarFiltroDeNombre, filtrar } from './filtro'
import type { Registro } from '../../api/registros'

function reg(name: string, type: string): Registro {
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

const REGISTROS = [
  reg('casa.test', 'SOA'),
  reg('casa.test', 'NS'),
  reg('www.casa.test', 'A'),
  reg('www.casa.test', 'AAAA'),
  reg('mail.casa.test', 'A'),
  reg('*.casa.test', 'A'),
  reg('a.b.casa.test', 'A'),
]

describe('filtro de nombre', () => {
  it('sin comodín la comparación es EXACTA, no «contiene»', () => {
    expect(filtrar(REGISTROS, { nombre: 'www', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    // `w` does not find `www`: without a wildcard no prefix counts.
    expect(filtrar(REGISTROS, { nombre: 'w', tipo: '' }, 'casa.test')).toEqual([])
  })

  it('`@` es el ápice de la zona', () => {
    expect(filtrar(REGISTROS, { nombre: '@', tipo: '' }, 'casa.test').map((r) => r.type)).toEqual([
      'SOA',
      'NS',
    ])
  })

  it('`@` en la raíz es el nombre vacío', () => {
    expect(compilarFiltroDeNombre('@', '.').dominio).toBe('')
  })

  it('`*` busca el registro COMODÍN literal, no lista todo', () => {
    // The zone.js:3548 line that looks like a bug and is not.
    expect(filtrar(REGISTROS, { nombre: '*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      '*.casa.test',
    ])
  })

  it('un comodín en medio sí se comporta como glob', () => {
    expect(filtrar(REGISTROS, { nombre: 'w*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'www.casa.test',
      'www.casa.test',
    ])
    expect(filtrar(REGISTROS, { nombre: 'a.*', tipo: '' }, 'casa.test').map((r) => r.name)).toEqual([
      'a.b.casa.test',
    ])
  })

  it('`?` sustituye un carácter', () => {
    expect(filtrar(REGISTROS, { nombre: 'ww?', tipo: '' }, 'casa.test')).toHaveLength(2)
  })

  it('lo escrito se pasa a minúsculas; el nombre de la zona NO', () => {
    // `filterName.toLowerCase()` yes, `zone` no (zone.js:3533). With the zone name
    // the server returns it makes no difference, but it is what the original does.
    expect(filtrar(REGISTROS, { nombre: 'WWW', tipo: '' }, 'casa.test')).toHaveLength(2)
    expect(compilarFiltroDeNombre('WWW', 'CASA.TEST').dominio).toBe('www.CASA.TEST')
  })
})

describe('filtro de tipo', () => {
  it('es exacto y en mayúsculas', () => {
    expect(filtrar(REGISTROS, { nombre: '', tipo: 'a' }, 'casa.test')).toHaveLength(4)
    expect(filtrar(REGISTROS, { nombre: '', tipo: 'AAAA' }, 'casa.test')).toHaveLength(1)
  })

  it('se combina con el de nombre', () => {
    expect(filtrar(REGISTROS, { nombre: 'www', tipo: 'A' }, 'casa.test')).toHaveLength(1)
  })

  it('sin filtros devuelve la misma lista, sin copiarla', () => {
    expect(filtrar(REGISTROS, { nombre: '', tipo: '' }, 'casa.test')).toBe(REGISTROS)
  })
})
