import { describe, expect, it, afterEach } from 'vitest'
import { SECTIONS } from './sections'
import { toTrail, aSlug, writeRoute, readRoute, forgetRoot, appRoot } from './route'

/** Serves the document as the server would: in its folder and with its meta. */
function servedAt(trail: string, route: string | null = null) {
  document.head.querySelector('meta[name="route"]')?.remove()
  if (route != null) {
    const m = document.createElement('meta')
    m.setAttribute('name', 'route')
    m.setAttribute('content', route)
    document.head.appendChild(m)
  }
  window.history.replaceState(null, '', trail)
  forgetRoot()
}

afterEach(() => {
  servedAt('/')
})

describe('aSlug', () => {
  it('it turns the upstream label into something that fits in a URL', () => {
    expect(aSlug('Leases')).toBe('leases')
    expect(aSlug('Web Service')).toBe('web-service')
    expect(aSlug('View Logs')).toBe('view-logs')
    // The `&` disappears instead of becoming a dash, so as not to leave `proxy--forwarders`
    expect(aSlug('Proxy & Forwarders')).toBe('proxy-forwarders')
    expect(aSlug('Optional Protocols')).toBe('optional-protocols')
  })

  it('every sub-section yields a distinct slug within its section', () => {
    for (const s of SECTIONS) {
      if (s.subs == null) continue
      const slugs = s.subs.map(aSlug)
      expect(new Set(slugs).size, `slug collision in ${s.id}: ${slugs.join(', ')}`).toBe(slugs.length)
    }
  })
})

/*
The console can hang off any prefix: the server honours `X-Forwarded-Prefix` by
mounting a `PathBase`. The root is deduced by subtracting from the `pathname` the
segments the document itself declares in its `<meta>`.
*/
describe('appRoot', () => {
  it('on the front page, the root is the front page', () => {
    servedAt('/')
    expect(appRoot()).toBe('/')
  })

  it('on a one-level path', () => {
    servedAt('/zones/', 'zones')
    expect(appRoot()).toBe('/')
  })

  it('on a two-level path', () => {
    servedAt('/settings/logging/', 'settings/logging')
    expect(appRoot()).toBe('/')
  })

  it('and behind a proxy with a prefix, which is what all this is about', () => {
    servedAt('/dns/settings/logging/', 'settings/logging')
    expect(appRoot()).toBe('/dns/')
  })

  it('with a two-segment prefix', () => {
    servedAt('/casa/dns/zones/', 'zones')
    expect(appRoot()).toBe('/casa/dns/')
  })
})

describe('readRoute', () => {
  it('on the front page there is no route, and it starts from whatever the Shell says', () => {
    servedAt('/')
    expect(readRoute(SECTIONS)).toBeNull()
  })

  it('it reads section and sub-section', () => {
    servedAt('/admin/cluster/', 'admin/cluster')
    expect(readRoute(SECTIONS)).toEqual({ section: 'admin', sub: 'Cluster' })
  })

  it('it returns the original label, not the slug', () => {
    servedAt('/settings/proxy-forwarders/', 'settings/proxy-forwarders')
    expect(readRoute(SECTIONS)).toEqual({ section: 'settings', sub: 'Proxy & Forwarders' })
  })

  it('it reads it the same behind a prefix', () => {
    servedAt('/dns/admin/cluster/', 'admin/cluster')
    expect(readRoute(SECTIONS)).toEqual({ section: 'admin', sub: 'Cluster' })
  })

  it('an unknown section does not resolve', () => {
    servedAt('/noexiste/', 'noexiste')
    expect(readRoute(SECTIONS)).toBeNull()
  })

  it('an unknown sub does NOT bring the section down: it falls to the first', () => {
    servedAt('/settings/tampoco-existe/', 'settings/tampoco-existe')
    expect(readRoute(SECTIONS)).toEqual({ section: 'settings', sub: null })
  })

  it('a section hidden by permissions does not resolve, even though it exists', () => {
    servedAt('/admin/cluster/', 'admin/cluster')
    expect(readRoute(SECTIONS.filter((s) => s.id !== 'admin'))).toBeNull()
  })
})

describe('toTrail', () => {
  it('it omits the sub when there is none, and always ends in a slash', () => {
    servedAt('/')
    expect(toTrail({ section: 'zones', sub: null })).toBe('/zones/')
  })

  it('and it slugs it when there is one', () => {
    servedAt('/')
    expect(toTrail({ section: 'logs', sub: 'Query Logs' })).toBe('/logs/query-logs/')
  })

  it('it honours the proxy prefix', () => {
    servedAt('/dns/zones/', 'zones')
    expect(toTrail({ section: 'settings', sub: 'TSIG' })).toBe('/dns/settings/tsig/')
  })
})

describe('writeRoute', () => {
  it('it leaves the address bar on the requested path', () => {
    servedAt('/')
    writeRoute({ section: 'dhcp', sub: 'Leases' }, true)
    expect(window.location.pathname).toBe('/dhcp/leases/')
  })

  it('it does not touch the history if the path is already the current one', () => {
    servedAt('/zones/', 'zones')
    const before2 = window.history.length
    writeRoute({ section: 'zones', sub: null })
    expect(window.location.pathname).toBe('/zones/')
    expect(window.history.length).toBe(before2)
  })

  it('what gets written reads back the same, across all 31 routes', () => {
    servedAt('/')
    for (const s of SECTIONS) {
      for (const sub of s.subs ?? [null]) {
        writeRoute({ section: s.id, sub }, true)
        expect(readRoute(SECTIONS)).toEqual({ section: s.id, sub })
      }
    }
  })
})

/*
El nombre del `<meta>` lo escribe el build y lo lee la aplicación, y son dos
ficheros distintos. Los casos de arriba no pueden ver esa junta porque escriben
el meta con el mismo nombre con el que lo leen: siempre están de acuerdo consigo
mismos.

Y esa junta se rompió de verdad. Al pasar `ruta` a `route`, `vite.config.ts`
empezó a emitir `<meta name="route">` mientras `app/base.ts` seguía buscando
`meta[name="ruta"]` —dentro de una cadena, que es justo donde el renombrado no
entra—. Resultado: la raíz caía al `pathname` completo y desde `/dhcp/scopes/`
la consola pedía `/dhcp/scopes/api/status`. 404 en 31 de las 32 rutas, con el
typecheck, el lint y las 821 pruebas en verde.

Este caso lee los dos ficheros de disco y comprueba que dicen el mismo nombre.
*/
describe('the `<meta>` name is the same on both sides of the build', () => {
  it('vite.config.ts writes the one app/base.ts reads', async () => {
    // `?raw` is Vite's own: it needs no extra dependency, and a dependency
    // would show up in the diff of the pull request.
    const config = (await import('../../vite.config.ts?raw')).default
    const reader = (await import('./base.ts?raw')).default

    const written = /<meta name="([^"]+)" content=/.exec(config)?.[1]
    const read = /meta\[name="([^"]+)"\]/.exec(reader)?.[1]

    expect(written, 'vite.config.ts no longer emits a route meta').toBeTruthy()
    expect(read, 'app/base.ts no longer reads a route meta').toBeTruthy()
    expect(read).toBe(written)
  })
})
