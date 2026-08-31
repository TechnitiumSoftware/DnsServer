import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  addDomain,
  deleteDomain,
  deleteCacheNode,
  parentDomain,
  exportDomains,
  importDomains,
  cleanList,
  listNode,
  flushCache,
  flushList,
} from './zonelists'
import * as client from './client'
import * as user from './user'

afterEach(() => vi.restoreAllMocks())

const RESPUESTA = {
  kind: 'ok' as const,
  data: { status: 'ok', response: { domain: 'casa.test', zones: ['a.casa.test'], records: [] } },
}

describe('listNode', () => {
  it('it calls the endpoint of each list with domain and node, like upstream', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)

    await listNode('cache', 't', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('cache/list')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test', node: '' })

    spy.mockClear()
    await listNode('allowed', 't', '')
    expect(spy.mock.calls[0][0]).toBe('allowed/list')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: '', node: '' })

    spy.mockClear()
    await listNode('blocked', 't', '')
    expect(spy.mock.calls[0][0]).toBe('blocked/list')
  })

  it('it only sends direction when navigating upwards', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)

    await listNode('cache', 't', 'casa.test')
    expect(spy.mock.calls[0][1]?.body?.direction).toBeUndefined()

    spy.mockClear()
    await listNode('cache', 't', 'casa.test', 'up')
    expect(spy.mock.calls[0][1]?.body?.direction).toBe('up')
  })

  /* other-zones.js:105 writes `domain.toLowerCase();` without assigning: in
     JavaScript strings are immutable, so the domain travels EXACTLY as typed. */
  it('it does not lowercase the domain: upstream does not either', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)
    await listNode('cache', 't', 'CASA.Test')
    expect(spy.mock.calls[0][1]?.body?.domain).toBe('CASA.Test')
  })

  it('it unwraps the node, which is what the screen needs', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)
    const r = await listNode('cache', 't', 'x')
    expect(r.kind).toBe('ok')
    if (r.kind !== 'ok') return
    expect(r.data.domain).toBe('casa.test')
    expect(r.data.zones).toEqual(['a.casa.test'])
  })

  /* Upstream draws the server's errorMessage when a list fails; with null that
     text would be lost. */
  it('it keeps the error message from the server', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    const r = await listNode('cache', 't', 'x')
    expect(r).toEqual({ kind: 'error', message: 'boom' })
  })
})

describe('parentDomain', () => {
  it('it replicates getParentDomain from other-zones.js', () => {
    expect(parentDomain('a.b.casa.test')).toBe('b.casa.test')
    expect(parentDomain('casa.test')).toBe('test')
    // A single-label domain has the root as its parent, which is "".
    expect(parentDomain('test')).toBe('')
    // The root has no parent: null, which is what hides the [up] link.
    expect(parentDomain('')).toBeNull()
    expect(parentDomain(null)).toBeNull()
  })
})

describe('cleanList', () => {
  it('it replicates cleanTextList from common.js', () => {
    expect(cleanList('a.test\nb.test')).toBe('a.test,b.test')
    expect(cleanList('a.test\n\n\nb.test')).toBe('a.test,b.test')
    expect(cleanList('\na.test\n')).toBe('a.test')
    expect(cleanList('')).toBe('')
    // A text of nothing but newlines collapses to an empty string: the comma at
    // the ends is stripped too. Upstream also checks `=== ","` when validating
    // the import; no input reaches that branch, but it is replicated all the same.
    expect(cleanList('\n')).toBe('')
    expect(cleanList('\n\n\n')).toBe('')
  })
})

describe('cache', () => {
  it('vaciarCache calls cache/flush with the cluster node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await flushCache('t')
    expect(spy.mock.calls[0][0]).toBe('cache/flush')
    expect(spy.mock.calls[0][1]?.body).toEqual({ node: '' })
  })

  it('borrarNodoCache calls cache/delete with domain and node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await deleteCacheNode('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('cache/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test', node: '' })
  })
})

describe('allowed and blocked', () => {
  it('anadirDominio and borrarDominio use the endpoint of their list', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })

    await addDomain('allowed', 't', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('allowed/add')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test' })

    spy.mockClear()
    await deleteDomain('blocked', 't', 'ads.test')
    expect(spy.mock.calls[0][0]).toBe('blocked/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'ads.test' })
  })

  /* the allowed/blocked flush does NOT carry `node`: upstream sends it on cache only. */
  it('vaciarLista no manda node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await flushList('blocked', 't')
    expect(spy.mock.calls[0][0]).toBe('blocked/flush')
    expect(spy.mock.calls[0][1]?.body).toBeUndefined()
  })

  it('importarDominios goes by POST and with the field name of each list', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })

    await importDomains('allowed', 't', 'a.test,b.test')
    expect(spy.mock.calls[0][0]).toBe('allowed/import')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(spy.mock.calls[0][1]?.body).toEqual({ allowedZones: 'a.test,b.test' })

    spy.mockClear()
    await importDomains('blocked', 't', 'c.test')
    expect(spy.mock.calls[0][1]?.body).toEqual({ blockedZones: 'c.test' })
  })

  /* The export does not go by XHR: it asks for a single-use token and opens a window. */
  it('exportarDominios goes through openDownload', async () => {
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })
    await exportDomains('allowed', 't')
    expect(spy.mock.calls[0][1]).toBe('allowed/export')
    spy.mockClear()
    await exportDomains('blocked', 't')
    expect(spy.mock.calls[0][1]).toBe('blocked/export')
  })
})
