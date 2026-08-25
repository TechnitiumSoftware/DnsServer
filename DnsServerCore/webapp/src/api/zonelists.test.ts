import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  anadirDominio,
  borrarDominio,
  borrarNodoCache,
  dominioPadre,
  exportarDominios,
  importarDominios,
  limpiarLista,
  listarNodo,
  vaciarCache,
  vaciarLista,
} from './zonelists'
import * as client from './client'
import * as user from './user'

afterEach(() => vi.restoreAllMocks())

const RESPUESTA = {
  kind: 'ok' as const,
  data: { status: 'ok', response: { domain: 'casa.test', zones: ['a.casa.test'], records: [] } },
}

describe('listarNodo', () => {
  it('llama al endpoint de cada lista con domain y node, como upstream', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)

    await listarNodo('cache', 't', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('cache/list')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test', node: '' })

    spy.mockClear()
    await listarNodo('allowed', 't', '')
    expect(spy.mock.calls[0][0]).toBe('allowed/list')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: '', node: '' })

    spy.mockClear()
    await listarNodo('blocked', 't', '')
    expect(spy.mock.calls[0][0]).toBe('blocked/list')
  })

  it('sólo manda direction cuando se navega hacia arriba', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)

    await listarNodo('cache', 't', 'casa.test')
    expect(spy.mock.calls[0][1]?.body?.direction).toBeUndefined()

    spy.mockClear()
    await listarNodo('cache', 't', 'casa.test', 'up')
    expect(spy.mock.calls[0][1]?.body?.direction).toBe('up')
  })

  /* other-zones.js:105 escribe `domain.toLowerCase();` sin asignar: en JavaScript
     las cadenas son inmutables, así que el dominio viaja TAL CUAL se escribió. */
  it('no pasa el dominio a minúsculas: upstream tampoco lo hace', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)
    await listarNodo('cache', 't', 'CASA.Test')
    expect(spy.mock.calls[0][1]?.body?.domain).toBe('CASA.Test')
  })

  it('desenvuelve el nodo, que es lo que la pantalla necesita', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(RESPUESTA)
    const r = await listarNodo('cache', 't', 'x')
    expect(r.kind).toBe('ok')
    if (r.kind !== 'ok') return
    expect(r.data.domain).toBe('casa.test')
    expect(r.data.zones).toEqual(['a.casa.test'])
  })

  /* Upstream pinta el errorMessage del servidor cuando un list falla; con null
     ese texto se perdería. */
  it('conserva el mensaje de error del servidor', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    const r = await listarNodo('cache', 't', 'x')
    expect(r).toEqual({ kind: 'error', message: 'boom' })
  })
})

describe('dominioPadre', () => {
  it('replica getParentDomain de other-zones.js', () => {
    expect(dominioPadre('a.b.casa.test')).toBe('b.casa.test')
    expect(dominioPadre('casa.test')).toBe('test')
    // Un dominio de una sola etiqueta tiene por padre la raíz, que es "".
    expect(dominioPadre('test')).toBe('')
    // La raíz no tiene padre: null, que es lo que oculta el enlace [up].
    expect(dominioPadre('')).toBeNull()
    expect(dominioPadre(null)).toBeNull()
  })
})

describe('limpiarLista', () => {
  it('replica cleanTextList de common.js', () => {
    expect(limpiarLista('a.test\nb.test')).toBe('a.test,b.test')
    expect(limpiarLista('a.test\n\n\nb.test')).toBe('a.test,b.test')
    expect(limpiarLista('\na.test\n')).toBe('a.test')
    expect(limpiarLista('')).toBe('')
    // Un texto de sólo saltos de línea colapsa a cadena vacía: la coma de los
    // extremos también se quita. Upstream comprueba además `=== ","` al validar
    // el import; esa rama no la alcanza ninguna entrada, pero se replica igual.
    expect(limpiarLista('\n')).toBe('')
    expect(limpiarLista('\n\n\n')).toBe('')
  })
})

describe('cache', () => {
  it('vaciarCache llama a cache/flush con el nodo del cluster', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await vaciarCache('t')
    expect(spy.mock.calls[0][0]).toBe('cache/flush')
    expect(spy.mock.calls[0][1]?.body).toEqual({ node: '' })
  })

  it('borrarNodoCache llama a cache/delete con domain y node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await borrarNodoCache('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('cache/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test', node: '' })
  })
})

describe('allowed y blocked', () => {
  it('anadirDominio y borrarDominio usan el endpoint de su lista', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })

    await anadirDominio('allowed', 't', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('allowed/add')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test' })

    spy.mockClear()
    await borrarDominio('blocked', 't', 'ads.test')
    expect(spy.mock.calls[0][0]).toBe('blocked/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'ads.test' })
  })

  /* flush de allowed/blocked NO lleva `node`: upstream lo manda sólo en cache. */
  it('vaciarLista no manda node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await vaciarLista('blocked', 't')
    expect(spy.mock.calls[0][0]).toBe('blocked/flush')
    expect(spy.mock.calls[0][1]?.body).toBeUndefined()
  })

  it('importarDominios va por POST y con el nombre de campo de cada lista', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })

    await importarDominios('allowed', 't', 'a.test,b.test')
    expect(spy.mock.calls[0][0]).toBe('allowed/import')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(spy.mock.calls[0][1]?.body).toEqual({ allowedZones: 'a.test,b.test' })

    spy.mockClear()
    await importarDominios('blocked', 't', 'c.test')
    expect(spy.mock.calls[0][1]?.body).toEqual({ blockedZones: 'c.test' })
  })

  /* La exportación no va por XHR: pide un token de un solo uso y abre ventana. */
  it('exportarDominios pasa por openDownload', async () => {
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })
    await exportarDominios('allowed', 't')
    expect(spy.mock.calls[0][1]).toBe('allowed/export')
    spy.mockClear()
    await exportarDominios('blocked', 't')
    expect(spy.mock.calls[0][1]).toBe('blocked/export')
  })
})
