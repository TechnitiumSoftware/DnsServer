import { describe, expect, it, afterEach } from 'vitest'
import { SECTIONS } from './sections'
import { toTrail, aSlug, escribirRuta, readRoute, forgetRoot, raizDeLaApp } from './route'

/** Serves the document as the server would: in its folder and with its meta. */
function servedAt(trail: string, route: string | null = null) {
  document.head.querySelector('meta[name="ruta"]')?.remove()
  if (route != null) {
    const m = document.createElement('meta')
    m.setAttribute('name', 'ruta')
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
  it('on the front page, the root is the front page', () => {
    servedAt('/')
    expect(raizDeLaApp()).toBe('/')
  })

  it('on a one-level path', () => {
    servedAt('/zones/', 'zones')
    expect(raizDeLaApp()).toBe('/')
  })

  it('on a two-level path', () => {
    servedAt('/settings/logging/', 'settings/logging')
    expect(raizDeLaApp()).toBe('/')
  })

  it('and behind a proxy with a prefix, which is what all this is about', () => {
    servedAt('/dns/settings/logging/', 'settings/logging')
    expect(raizDeLaApp()).toBe('/dns/')
  })

  it('with a two-segment prefix', () => {
    servedAt('/casa/dns/zones/', 'zones')
    expect(raizDeLaApp()).toBe('/casa/dns/')
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

describe('escribirRuta', () => {
  it('it leaves the address bar on the requested path', () => {
    servedAt('/')
    escribirRuta({ section: 'dhcp', sub: 'Leases' }, true)
    expect(window.location.pathname).toBe('/dhcp/leases/')
  })

  it('it does not touch the history if the path is already the current one', () => {
    servedAt('/zones/', 'zones')
    const before2 = window.history.length
    escribirRuta({ section: 'zones', sub: null })
    expect(window.location.pathname).toBe('/zones/')
    expect(window.history.length).toBe(before2)
  })

  it('what gets written reads back the same, across all 31 routes', () => {
    servedAt('/')
    for (const s of SECTIONS) {
      for (const sub of s.subs ?? [null]) {
        escribirRuta({ section: s.id, sub }, true)
        expect(readRoute(SECTIONS)).toEqual({ section: s.id, sub })
      }
    }
  })
})
