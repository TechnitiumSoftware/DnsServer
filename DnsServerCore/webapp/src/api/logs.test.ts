import { describe, expect, it, vi, afterEach } from 'vitest'
import * as client from './client'
import * as user from './user'
import {
  deleteAllLogs,
  deleteLog,
  downloadLogText,
  exportLogsCsv,
  listLogFiles,
  openLogDownload,
  queryLogs,
  type QueryLogsParams,
} from './logs'

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function ok(data: unknown) {
  return { kind: 'ok' as const, data }
}

const FILTROS: QueryLogsParams = {
  name: 'Query Logs (Sqlite)',
  classPath: 'QueryLogsSqlite.App',
  pageNumber: '1',
  entriesPerPage: '25',
  descendingOrder: 'true',
  start: '',
  end: '',
  clientIpAddress: '',
  protocol: '',
  responseType: '',
  rcode: '',
  qname: '',
  qtype: '',
  qclass: '',
}

describe('api/logs — ficheros', () => {
  it('logs/list pide el nodo y devuelve los ficheros', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ response: { logFiles: [{ fileName: '2026-08-26', size: '2.96 KB' }] } }),
    )

    const ficheros = await listLogFiles('tok')

    expect(spy.mock.calls.find((c) => c[0] === 'logs/list')![1]?.body).toEqual({ node: '' })
    expect(ficheros[0].fileName).toBe('2026-08-26')
  })

  it('logs/list devuelve lista vacía si el servidor falla', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listLogFiles('tok')).toEqual([])
  })

  it('logs/delete manda el fichero en `log`, NO en `fileName`', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    await deleteLog('tok', '2026-08-26')
    expect(spy.mock.calls.find((c) => c[0] === 'logs/delete')![1]?.body).toEqual({
      log: '2026-08-26',
      node: '',
    })
  })

  it('logs/deleteAll sólo manda el nodo', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    await deleteAllLogs('tok')
    expect(spy.mock.calls.find((c) => c[0] === 'logs/deleteAll')![1]?.body).toEqual({ node: '' })
  })
})

describe('api/logs — descarga del visor', () => {
  it('pide los 2 primeros MB con el token en la cabecera y devuelve el texto', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ text: () => Promise.resolve('[2026] ok\n') })
    vi.stubGlobal('fetch', fetchSpy)

    const texto = await downloadLogText('tok', '2026-08-26')

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('api/logs/download?fileName=2026-08-26&limit=2&node=')
    expect(init.headers).toEqual({ Authorization: 'Bearer tok' })
    expect(texto).toBe('[2026] ok\n')
  })

  it('si el servidor responde un error JSON lo devuelve FORMATEADO, para pintarlo en el visor', async () => {
    const cuerpo = JSON.stringify({ status: 'error', errorMessage: "Could not find file 'x'." })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ text: () => Promise.resolve(cuerpo) }))

    const texto = await downloadLogText('tok', 'nope')

    expect(texto).toBe(JSON.stringify(JSON.parse(cuerpo), null, 2))
    expect(texto).toContain('"status": "error"')
  })

  it('devuelve null si la petición ni siquiera sale', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    expect(await downloadLogText('tok', '2026-08-26')).toBeNull()
  })

  it('el botón Download pide el fichero ENTERO, con `ts` y sin `limit`', async () => {
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })

    await openLogDownload('tok', '2026-08-26', 'nodo-1')

    expect(spy).toHaveBeenCalledWith(
      'tok',
      'logs/download',
      { fileName: '2026-08-26', node: 'nodo-1' },
      { ts: true },
    )
  })
})

describe('api/logs — consulta y exportación', () => {
  it('logs/query manda los catorce filtros más el nodo', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { pageNumber: 1, totalPages: 1, totalEntries: 0, entries: [] } }))

    await queryLogs('tok', FILTROS)

    expect(spy.mock.calls.find((c) => c[0] === 'logs/query')![1]?.body).toEqual({
      ...FILTROS,
      node: '',
    })
  })

  it('logs/export NO manda los tres parámetros de paginación ni `ts`', async () => {
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })

    await exportLogsCsv('tok', { ...FILTROS, qname: 'casa.test' })

    const [, ruta, params, opciones] = spy.mock.calls[0]
    expect(ruta).toBe('logs/export')
    expect(params).not.toHaveProperty('pageNumber')
    expect(params).not.toHaveProperty('entriesPerPage')
    expect(params).not.toHaveProperty('descendingOrder')
    expect(params).toMatchObject({ name: 'Query Logs (Sqlite)', qname: 'casa.test', node: '' })
    expect(opciones).toBeUndefined()
  })
})
