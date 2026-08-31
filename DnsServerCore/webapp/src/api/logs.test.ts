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

describe('api/logs — files', () => {
  it('logs/list asks for the node and returns the files', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(
      ok({ response: { logFiles: [{ fileName: '2026-08-26', size: '2.96 KB' }] } }),
    )

    const ficheros = await listLogFiles('tok')

    expect(spy.mock.calls.find((c) => c[0] === 'logs/list')![1]?.body).toEqual({ node: '' })
    expect(ficheros.kind === 'ok' && ficheros.data[0].fileName).toBe('2026-08-26')
  })

  /*
  This test claimed the opposite —"returns an empty list if the server fails"—
  and was pinning the bug in place: an empty list and a fallen call draw the
  same, so the screen said "No Log File Was Found" when what had happened was
  that there was no response. Now the failure rises as it is, with its message,
  and it is the screen that decides what to show.
  */
  it('logs/list raises the failure from the server, not an empty list', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await listLogFiles('tok')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('logs/delete sends the file in `log`, NOT in `fileName`', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    await deleteLog('tok', '2026-08-26')
    expect(spy.mock.calls.find((c) => c[0] === 'logs/delete')![1]?.body).toEqual({
      log: '2026-08-26',
      node: '',
    })
  })

  it('logs/deleteAll only sends the node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    await deleteAllLogs('tok')
    expect(spy.mock.calls.find((c) => c[0] === 'logs/deleteAll')![1]?.body).toEqual({ node: '' })
  })
})

describe('api/logs — download for the viewer', () => {
  it('asks for the first 2 MB with the token in the header and returns the text', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ text: () => Promise.resolve('[2026] ok\n') })
    vi.stubGlobal('fetch', fetchSpy)

    const text = await downloadLogText('tok', '2026-08-26')

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe('/api/logs/download?fileName=2026-08-26&limit=2&node=')
    expect(init.headers).toEqual({ Authorization: 'Bearer tok' })
    expect(text).toBe('[2026] ok\n')
  })

  it('if the server answers a JSON error it returns it FORMATTED, to draw in the viewer', async () => {
    const body = JSON.stringify({ status: 'error', errorMessage: "Could not find file 'x'." })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ text: () => Promise.resolve(body) }))

    const text = await downloadLogText('tok', 'nope')

    expect(text).toBe(JSON.stringify(JSON.parse(body), null, 2))
    expect(text).toContain('"status": "error"')
  })

  it('returns null if the request does not even go out', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    expect(await downloadLogText('tok', '2026-08-26')).toBeNull()
  })

  it('the Download button asks for the WHOLE file, with `ts` and without `limit`', async () => {
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

describe('api/logs — query and export', () => {
  it('logs/query sends the fourteen filters plus the node', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { pageNumber: 1, totalPages: 1, totalEntries: 0, entries: [] } }))

    await queryLogs('tok', FILTROS)

    expect(spy.mock.calls.find((c) => c[0] === 'logs/query')![1]?.body).toEqual({
      ...FILTROS,
      node: '',
    })
  })

  it('logs/export does NOT send the three paging parameters nor `ts`', async () => {
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })

    await exportLogsCsv('tok', { ...FILTROS, qname: 'casa.test' })

    const [, route, params, options] = spy.mock.calls[0]
    expect(route).toBe('logs/export')
    expect(params).not.toHaveProperty('pageNumber')
    expect(params).not.toHaveProperty('entriesPerPage')
    expect(params).not.toHaveProperty('descendingOrder')
    expect(params).toMatchObject({ name: 'Query Logs (Sqlite)', qname: 'casa.test', node: '' })
    expect(options).toBeUndefined()
  })
})
