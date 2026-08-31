import { describe, expect, it } from 'vitest'
import { textoDeEstado, ventanaDePaginas } from './paginacion'

describe('ventana de páginas', () => {
  it('con menos de diez páginas se ven todas', () => {
    expect(ventanaDePaginas(1, 3).paginas).toEqual([1, 2, 3])
  })

  it('centra cinco páginas antes de la actual', () => {
    expect(ventanaDePaginas(20, 50).paginas).toEqual([15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
  })

  it('en la última página SE DESPLAZA HACIA ATRÁS y enseña las diez últimas', () => {
    // The case that gets lost when "simplifying" the arithmetic: without the
    // adjustment, the last page would show a single one.
    expect(ventanaDePaginas(50, 50).paginas).toEqual([41, 42, 43, 44, 45, 46, 47, 48, 49, 50])
  })

  it('en la primera no ofrece «anterior» ni «primera»', () => {
    const p = ventanaDePaginas(1, 5)
    expect(p.primera).toBe(false)
    expect(p.anterior).toBeNull()
    expect(p.siguiente).toBe(2)
    expect(p.ultima).toBe(true)
  })

  it('en la última no ofrece «siguiente» ni «última»', () => {
    const p = ventanaDePaginas(5, 5)
    expect(p.siguiente).toBeNull()
    expect(p.ultima).toBe(false)
  })
})

describe('texto de estado', () => {
  it('con elementos dice el rango, el total y la página', () => {
    expect(textoDeEstado(11, 10, 47, 2, 5, 'zones')).toBe('11-20 (10) of 47 zones (page 2 of 5)')
  })

  it('sin elementos la frase entera cambia', () => {
    expect(textoDeEstado(1, 0, 0, 1, 1, 'records')).toBe('0 records')
  })
})
