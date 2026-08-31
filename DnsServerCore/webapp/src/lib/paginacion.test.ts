import { describe, expect, it } from 'vitest'
import { textoDeEstado, ventanaDePaginas } from './paginacion'

describe('page window', () => {
  it('with fewer than ten pages they are all visible', () => {
    expect(ventanaDePaginas(1, 3).paginas).toEqual([1, 2, 3])
  })

  it('it centres five pages before the current one', () => {
    expect(ventanaDePaginas(20, 50).paginas).toEqual([15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
  })

  it('on the last page it SLIDES BACKWARDS and shows the last ten', () => {
    // The case that gets lost when "simplifying" the arithmetic: without the
    // adjustment, the last page would show a single one.
    expect(ventanaDePaginas(50, 50).paginas).toEqual([41, 42, 43, 44, 45, 46, 47, 48, 49, 50])
  })

  it('on the first it offers neither "previous" nor "first"', () => {
    const p = ventanaDePaginas(1, 5)
    expect(p.primera).toBe(false)
    expect(p.anterior).toBeNull()
    expect(p.siguiente).toBe(2)
    expect(p.ultima).toBe(true)
  })

  it('on the last it offers neither "next" nor "last"', () => {
    const p = ventanaDePaginas(5, 5)
    expect(p.siguiente).toBeNull()
    expect(p.ultima).toBe(false)
  })
})

describe('status text', () => {
  it('with items it states the range, the total and the page', () => {
    expect(textoDeEstado(11, 10, 47, 2, 5, 'zones')).toBe('11-20 (10) of 47 zones (page 2 of 5)')
  })

  it('with no items the whole sentence changes', () => {
    expect(textoDeEstado(1, 0, 0, 1, 1, 'records')).toBe('0 records')
  })
})
