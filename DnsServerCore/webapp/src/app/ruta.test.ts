import { describe, expect, it, afterEach } from 'vitest'
import { SECTIONS } from './sections'
import { aCamino, aSlug, escribirRuta, leerRuta, olvidarRaiz, raizDeLaApp } from './ruta'

/** Serves the document as the server would: in its folder and with its meta. */
function servidoEn(camino: string, ruta: string | null = null) {
  document.head.querySelector('meta[name="ruta"]')?.remove()
  if (ruta != null) {
    const m = document.createElement('meta')
    m.setAttribute('name', 'ruta')
    m.setAttribute('content', ruta)
    document.head.appendChild(m)
  }
  window.history.replaceState(null, '', camino)
  olvidarRaiz()
}

afterEach(() => {
  servidoEn('/')
})

describe('aSlug', () => {
  it('convierte la etiqueta de upstream en algo que cabe en una URL', () => {
    expect(aSlug('Leases')).toBe('leases')
    expect(aSlug('Web Service')).toBe('web-service')
    expect(aSlug('View Logs')).toBe('view-logs')
    // The `&` disappears instead of becoming a dash, so as not to leave `proxy--forwarders`
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

/*
The console can hang off any prefix: the server honours `X-Forwarded-Prefix` by
mounting a `PathBase`. The root is deduced by subtracting from the `pathname` the
segments the document itself declares in its `<meta>`.
*/
describe('raizDeLaApp', () => {
  it('en la portada, la raíz es la portada', () => {
    servidoEn('/')
    expect(raizDeLaApp()).toBe('/')
  })

  it('en una ruta de un nivel', () => {
    servidoEn('/zones/', 'zones')
    expect(raizDeLaApp()).toBe('/')
  })

  it('en una ruta de dos niveles', () => {
    servidoEn('/settings/logging/', 'settings/logging')
    expect(raizDeLaApp()).toBe('/')
  })

  it('y detrás de un proxy con prefijo, que es de lo que va todo esto', () => {
    servidoEn('/dns/settings/logging/', 'settings/logging')
    expect(raizDeLaApp()).toBe('/dns/')
  })

  it('con prefijo de dos segmentos', () => {
    servidoEn('/casa/dns/zones/', 'zones')
    expect(raizDeLaApp()).toBe('/casa/dns/')
  })
})

describe('leerRuta', () => {
  it('en la portada no hay ruta, y se arranca por lo que diga el Shell', () => {
    servidoEn('/')
    expect(leerRuta(SECTIONS)).toBeNull()
  })

  it('lee sección y sub-sección', () => {
    servidoEn('/admin/cluster/', 'admin/cluster')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'admin', sub: 'Cluster' })
  })

  it('devuelve la etiqueta original, no el slug', () => {
    servidoEn('/settings/proxy-forwarders/', 'settings/proxy-forwarders')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'settings', sub: 'Proxy & Forwarders' })
  })

  it('la lee igual detrás de un prefijo', () => {
    servidoEn('/dns/admin/cluster/', 'admin/cluster')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'admin', sub: 'Cluster' })
  })

  it('una sección desconocida no resuelve', () => {
    servidoEn('/noexiste/', 'noexiste')
    expect(leerRuta(SECTIONS)).toBeNull()
  })

  it('una sub desconocida NO tumba la sección: cae a la primera', () => {
    servidoEn('/settings/tampoco-existe/', 'settings/tampoco-existe')
    expect(leerRuta(SECTIONS)).toEqual({ seccion: 'settings', sub: null })
  })

  it('una sección oculta por permisos no resuelve, aunque exista', () => {
    servidoEn('/admin/cluster/', 'admin/cluster')
    expect(leerRuta(SECTIONS.filter((s) => s.id !== 'admin'))).toBeNull()
  })
})

describe('aCamino', () => {
  it('omite la sub cuando no la hay, y siempre termina en barra', () => {
    servidoEn('/')
    expect(aCamino({ seccion: 'zones', sub: null })).toBe('/zones/')
  })

  it('y la pone en slug cuando la hay', () => {
    servidoEn('/')
    expect(aCamino({ seccion: 'logs', sub: 'Query Logs' })).toBe('/logs/query-logs/')
  })

  it('respeta el prefijo del proxy', () => {
    servidoEn('/dns/zones/', 'zones')
    expect(aCamino({ seccion: 'settings', sub: 'TSIG' })).toBe('/dns/settings/tsig/')
  })
})

describe('escribirRuta', () => {
  it('deja la barra de direcciones en la ruta pedida', () => {
    servidoEn('/')
    escribirRuta({ seccion: 'dhcp', sub: 'Leases' }, true)
    expect(window.location.pathname).toBe('/dhcp/leases/')
  })

  it('no toca el historial si la ruta ya es la que está', () => {
    servidoEn('/zones/', 'zones')
    const antes = window.history.length
    escribirRuta({ seccion: 'zones', sub: null })
    expect(window.location.pathname).toBe('/zones/')
    expect(window.history.length).toBe(antes)
  })

  it('lo que se escribe se vuelve a leer igual, en las 31 rutas', () => {
    servidoEn('/')
    for (const s of SECTIONS) {
      for (const sub of s.subs ?? [null]) {
        escribirRuta({ seccion: s.id, sub }, true)
        expect(leerRuta(SECTIONS)).toEqual({ seccion: s.id, sub })
      }
    }
  })
})
