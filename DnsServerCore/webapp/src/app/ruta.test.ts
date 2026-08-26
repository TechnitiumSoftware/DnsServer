import { describe, expect, it, afterEach } from 'vitest'
import { SECTIONS } from './sections'
import { aHash, aSlug, escribirRuta, leerRuta } from './ruta'

function conHash(h: string) {
  window.history.replaceState(null, '', h === '' ? window.location.pathname : h)
}

afterEach(() => {
  conHash('')
})

describe('aSlug', () => {
  it('convierte la etiqueta de upstream en algo que cabe en una URL', () => {
    expect(aSlug('Leases')).toBe('leases')
    expect(aSlug('Web Service')).toBe('web-service')
    expect(aSlug('View Logs')).toBe('view-logs')
    // El `&` desaparece en vez de convertirse en guion, para no dejar `proxy--forwarders`
    expect(aSlug('Proxy & Forwarders')).toBe('proxy-forwarders')
    expect(aSlug('Optional Protocols')).toBe('optional-protocols')
  })

  it('todas las sub-secciones dan un slug distinto dentro de su sección', () => {
    for (const s of SECTIONS) {
      if (s.subs == null) continue
      const slugs = s.subs.map(aSlug)
      expect(new Set(slugs).size, `colisión en ${s.id}: ${slugs.join(', ')}`).toBe(slugs.length)
    }
  })
})

describe('leerRuta', () => {
  it('sin hash no hay ruta, y se arranca por lo que diga el Shell', () => {
    conHash('')
    expect(leerRuta(SECTIONS)).toBeNull()
  })

  it('lee sección y sub-sección', () => {
    conHash('#/admin/cluster')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'admin', sub: 'Cluster' })
  })

  it('devuelve la etiqueta original, no el slug', () => {
    conHash('#/settings/proxy-forwarders')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'settings', sub: 'Proxy & Forwarders' })
  })

  it('una sección desconocida no resuelve', () => {
    conHash('#/noexiste')
    expect(leerRuta(SECTIONS)).toBeNull()
  })

  it('una sub desconocida NO tumba la sección: cae a la primera', () => {
    conHash('#/settings/tampoco-existe')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'settings', sub: null })
  })

  it('una sección oculta por permisos no resuelve, aunque exista', () => {
    const visibles = SECTIONS.filter((s) => s.id !== 'admin')
    conHash('#/admin/cluster')
    expect(leerRuta(visibles)).toBeNull()
  })

  /*
  El motivo de que las rutas lleven `#/`: el proveedor de SSO devuelve al usuario
  con `#token=…` o `#error=…`, y `session/boot.ts` tiene que poder distinguir lo
  que hay que borrar de la barra de lo que hay que conservar.
  */
  it('el retorno de SSO no se confunde con una ruta', () => {
    conHash('#token=abc123')
    expect(leerRuta(SECTIONS)).toBeNull()
    conHash('#error=Invalid%20request')
    expect(leerRuta(SECTIONS)).toBeNull()
  })
})

describe('aHash', () => {
  it('omite la sub cuando no la hay', () => {
    expect(aHash({ seccion: 'zones', sub: null })).toBe('#/zones')
  })

  it('y la pone en slug cuando la hay', () => {
    expect(aHash({ seccion: 'logs', sub: 'Query Logs' })).toBe('#/logs/query-logs')
  })
})

describe('escribirRuta', () => {
  it('deja la barra de direcciones en la ruta pedida', () => {
    conHash('')
    escribirRuta({ seccion: 'dhcp', sub: 'Leases' }, true)
    expect(window.location.hash).toBe('#/dhcp/leases')
  })

  it('no toca el historial si la ruta ya es la que está', () => {
    conHash('#/zones')
    const antes = window.history.length
    escribirRuta({ seccion: 'zones', sub: null })
    expect(window.location.hash).toBe('#/zones')
    expect(window.history.length).toBe(antes)
  })

  it('lo que se escribe se vuelve a leer igual', () => {
    for (const s of SECTIONS) {
      for (const sub of s.subs ?? [null]) {
        escribirRuta({ seccion: s.id, sub }, true)
        expect(leerRuta(SECTIONS)).toEqual({ seccion: s.id, sub })
      }
    }
  })
})
