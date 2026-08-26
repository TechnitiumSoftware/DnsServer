import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Logs } from './Logs'
import * as api from '../../api/logs'
import * as dashboard from '../../api/dashboard'
import * as apps from '../../api/apps'
import type { InstalledApp } from '../../api/apps'
import type { QueryLogEntry, QueryLogPage } from '../../api/logs'
import { claseFila, rangoPaginas, textoEstado } from './QueryLogs'

afterEach(() => vi.restoreAllMocks())

const OK = { kind: 'ok' as const, data: {} }

const FICHEROS = [
  { fileName: '2026-08-26', size: '2.96 KB' },
  { fileName: '2026-08-25', size: '20.48 KB' },
]

const DETALLE = {
  classPath: 'QueryLogsSqlite.App',
  description: 'Logs queries.',
  recordDataTemplate: null,
  isAppRecordRequestHandler: false,
  isRequestController: false,
  isAuthoritativeRequestHandler: false,
  isRequestBlockingHandler: false,
  isQueryLogger: true,
  isQueryLogs: true,
  isPostProcessor: false,
}

const APP: InstalledApp = {
  name: 'Query Logs (Sqlite)',
  description: 'Logs all incoming DNS requests.',
  version: '8.0',
  dnsApps: [DETALLE],
}

const SIN_QUERY_LOGS: InstalledApp = {
  name: 'NO DATA',
  description: 'Returns NO DATA.',
  version: '5.0',
  dnsApps: [{ ...DETALLE, classPath: 'NoData.App', isQueryLogs: false }],
}

const ENTRADA: QueryLogEntry = {
  rowNumber: 10,
  timestamp: '2026-08-26T05:32:14.1836952Z',
  clientIpAddress: '127.0.0.1',
  protocol: 'Udp',
  responseType: 'Recursive',
  responseRtt: 12.8186,
  rcode: 'NoError',
  qname: 'github.com',
  qtype: 'A',
  qclass: 'IN',
  answer: 'A 140.82.121.3',
}

function pagina(parcial: Partial<QueryLogPage> = {}): QueryLogPage {
  return { pageNumber: 1, totalPages: 1, totalEntries: 1, entries: [ENTRADA], ...parcial }
}

function conApps(lista: InstalledApp[]) {
  return vi
    .spyOn(apps, 'listApps')
    .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: { apps: lista } } } as never)
}

describe('Logs › View Logs', () => {
  it('lista los ficheros con su tamaño y ofrece borrarlos todos', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    render(<Logs token="t" sub="View Logs" />)

    expect(await screen.findByText('2026-08-26')).toBeInTheDocument()
    expect(screen.getByText('[20.48 KB]')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Logs' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Stats' })).toBeInTheDocument()
  })

  it('sin ficheros dice «No Log File Was Found» y desaparece «Delete All Logs», pero NO «Delete All Stats»', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue([])
    render(<Logs token="t" sub="View Logs" />)

    expect(await screen.findByText('No Log File Was Found')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete All Logs' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Stats' })).toBeInTheDocument()
  })

  it('abrir un fichero pide sólo los 2 primeros MB y lo pinta', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    const spy = vi.spyOn(api, 'downloadLogText').mockResolvedValue('[2026-08-26] Logging started.')
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')

    await user.click(screen.getByText('2026-08-26'))

    expect(spy).toHaveBeenCalledWith('t', '2026-08-26', '')
    expect(await screen.findByText('[2026-08-26] Logging started.')).toBeInTheDocument()
  })

  it('«Download» pide el fichero entero por token de un solo uso', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    vi.spyOn(api, 'downloadLogText').mockResolvedValue('x')
    const spy = vi.spyOn(api, 'openLogDownload').mockResolvedValue({ ok: true })
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')
    await user.click(screen.getByText('2026-08-26'))
    await screen.findByText('x')

    await user.click(screen.getByRole('button', { name: 'Download' }))

    expect(spy).toHaveBeenCalledWith('t', '2026-08-26', '')
  })

  it('borrar un fichero confirma con su nombre y avisa con el texto literal', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    vi.spyOn(api, 'downloadLogText').mockResolvedValue('x')
    const spy = vi.spyOn(api, 'deleteLog').mockResolvedValue(OK)
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')
    await user.click(screen.getByText('2026-08-26'))
    await screen.findByText('x')

    await user.click(screen.getByRole('button', { name: 'Delete' }))
    expect(
      screen.getByText("Are you sure you want to permanently delete the log file '2026-08-26'?"),
    ).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    expect(spy).toHaveBeenCalledWith('t', '2026-08-26', '')
    expect(await screen.findByText('Log Deleted!')).toBeInTheDocument()
    expect(screen.getByText('Log file was deleted successfully.')).toBeInTheDocument()
  })

  it('«Delete All Logs» confirma y avisa con «Logs Deleted!»', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    const spy = vi.spyOn(api, 'deleteAllLogs').mockResolvedValue(OK)
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')

    await user.click(screen.getByRole('button', { name: 'Delete All Logs' }))
    expect(
      screen.getByText('Are you sure you want to permanently delete all log files?'),
    ).toBeInTheDocument()
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete All Logs' }),
    )

    expect(spy).toHaveBeenCalledWith('t', '')
    expect(await screen.findByText('Logs Deleted!')).toBeInTheDocument()
    expect(screen.getByText('All log files were deleted successfully.')).toBeInTheDocument()
  })

  it('«Delete All Stats» llama al endpoint del DASHBOARD, no al de logs', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    const spy = vi.spyOn(dashboard, 'deleteAllStats').mockResolvedValue(OK)
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')

    await user.click(screen.getByRole('button', { name: 'Delete All Stats' }))
    expect(
      screen.getByText('Are you sure you want to permanently delete all stats files?'),
    ).toBeInTheDocument()
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete All Stats' }),
    )

    expect(spy).toHaveBeenCalledWith('t')
    expect(await screen.findByText('Stats Deleted!')).toBeInTheDocument()
    expect(screen.getByText('All stats files were deleted successfully.')).toBeInTheDocument()
  })

  it('los dos permisos de borrado son distintos y se aplican por separado', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue(FICHEROS)
    const { unmount } = render(
      <Logs token="t" sub="View Logs" canDeleteLogs={false} canDeleteStats />,
    )
    expect(await screen.findByRole('button', { name: 'Delete All Stats' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete All Logs' })).not.toBeInTheDocument()
    unmount()

    render(<Logs token="t" sub="View Logs" canDeleteLogs canDeleteStats={false} />)
    expect(await screen.findByRole('button', { name: 'Delete All Logs' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete All Stats' })).not.toBeInTheDocument()
  })
})

describe('Logs › Query Logs — el formulario', () => {
  it('sólo ofrece los apps que declaran `isQueryLogs`', async () => {
    conApps([SIN_QUERY_LOGS, APP])
    render(<Logs token="t" sub="Query Logs" />)

    const appName = (await screen.findByLabelText('App Name')) as HTMLSelectElement
    expect(within(appName).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'Query Logs (Sqlite)',
    ])
    expect(appName).toHaveValue('Query Logs (Sqlite)')
    expect(screen.getByLabelText('Class Path')).toHaveValue('QueryLogsSqlite.App')
  })

  it('los valores por defecto son los del formulario de upstream, no los del servidor', async () => {
    conApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    expect(screen.getByLabelText('Page Number')).toHaveValue(1)
    expect(screen.getByLabelText('Logs Per Page')).toHaveValue('10')
    expect(screen.getByLabelText('Order')).toHaveValue('true')
    expect(screen.getByLabelText('From')).toHaveValue('')
    expect(screen.getByLabelText('Domain')).toHaveValue('')
  })

  it('«Logs Per Page» se recuerda en localStorage con la clave de upstream', async () => {
    const user = userEvent.setup()
    conApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.selectOptions(screen.getByLabelText('Logs Per Page'), '100')

    expect(localStorage.getItem('optQueryLogsEntriesPerPage')).toBe('100')
    localStorage.removeItem('optQueryLogsEntriesPerPage')
  })

  it('«Query» manda los catorce filtros con los valores del formulario', async () => {
    const user = userEvent.setup()
    conApps([APP])
    const spy = vi
      .spyOn(api, 'queryLogs')
      .mockResolvedValue({ kind: 'ok', data: { response: pagina() } } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.type(screen.getByLabelText('Domain'), 'casa.test')
    await user.selectOptions(screen.getByLabelText('Protocol'), 'Udp')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(spy.mock.calls[0][1]).toEqual({
      name: 'Query Logs (Sqlite)',
      classPath: 'QueryLogsSqlite.App',
      pageNumber: '1',
      entriesPerPage: '10',
      descendingOrder: 'true',
      start: '',
      end: '',
      clientIpAddress: '',
      protocol: 'Udp',
      responseType: '',
      rcode: '',
      qname: 'casa.test',
      qtype: '',
      qclass: '',
      node: '',
    })
  })

  it('sin ningún app de query logs, «Query» avisa con el texto que remite a Apps', async () => {
    const user = userEvent.setup()
    conApps([SIN_QUERY_LOGS])
    const spy = vi.spyOn(api, 'queryLogs')
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(spy).not.toHaveBeenCalled()
    expect(screen.getByText('Missing!')).toBeInTheDocument()
    expect(
      screen.getByText(
        "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature from the Apps section.",
      ),
    ).toBeInTheDocument()
  })

  it('«Export» avisa con el MISMO título pero SIN «from the Apps section.»', async () => {
    const user = userEvent.setup()
    conApps([SIN_QUERY_LOGS])
    const spy = vi.spyOn(api, 'exportLogsCsv')
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.click(screen.getByRole('button', { name: 'Export' }))

    expect(spy).not.toHaveBeenCalled()
    expect(
      screen.getByText(
        "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature.",
      ),
    ).toBeInTheDocument()
  })

  it('«Export» con un app válido llama al endpoint de exportación', async () => {
    const user = userEvent.setup()
    conApps([APP])
    const spy = vi.spyOn(api, 'exportLogsCsv').mockResolvedValue({ ok: true })
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.click(screen.getByRole('button', { name: 'Export' }))

    expect(spy.mock.calls[0][1]).toMatchObject({
      name: 'Query Logs (Sqlite)',
      classPath: 'QueryLogsSqlite.App',
    })
  })

  it('«Reset» devuelve el formulario a sus valores por defecto', async () => {
    const user = userEvent.setup()
    conApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.type(screen.getByLabelText('Domain'), 'casa.test')
    await user.selectOptions(screen.getByLabelText('Order'), 'false')
    await user.click(screen.getByRole('button', { name: 'Reset' }))

    expect(screen.getByLabelText('Domain')).toHaveValue('')
    expect(screen.getByLabelText('Order')).toHaveValue('true')
  })

  it('«Live Update» fija página y orden, vacía el rango y deshabilita esos cuatro controles', async () => {
    const user = userEvent.setup()
    conApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: pagina() },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.selectOptions(screen.getByLabelText('Order'), 'false')
    await user.type(screen.getByLabelText('From'), '2026-08-25T00:00')
    await user.click(screen.getByLabelText('Live Update'))

    expect(screen.getByLabelText('Order')).toHaveValue('true')
    expect(screen.getByLabelText('From')).toHaveValue('')
    expect(screen.getByLabelText('Page Number')).toBeDisabled()
    expect(screen.getByLabelText('Order')).toBeDisabled()
    expect(screen.getByLabelText('From')).toBeDisabled()
    expect(screen.getByLabelText('To')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Query' })).toBeDisabled()
  })

  it('«Live Update» vuelve a consultar cada 2 s, y parar lo corta', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const user = userEvent.setup({ delay: null })
      conApps([APP])
      const spy = vi.spyOn(api, 'queryLogs').mockResolvedValue({
        kind: 'ok',
        data: { response: pagina() },
      } as never)
      render(<Logs token="t" sub="Query Logs" />)
      await vi.waitFor(() => expect(screen.queryByLabelText('App Name')).toBeInTheDocument())

      await user.click(screen.getByLabelText('Live Update'))
      await vi.waitFor(() => expect(spy).toHaveBeenCalledTimes(1))

      await vi.advanceTimersByTimeAsync(2000)
      await vi.waitFor(() => expect(spy).toHaveBeenCalledTimes(2))

      await user.click(screen.getByLabelText('Live Update'))
      await vi.advanceTimersByTimeAsync(6000)
      expect(spy).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('Logs › Query Logs — la tabla', () => {
  it('pinta una fila por entrada, con el RTT y la marca de tiempo formateada', async () => {
    const user = userEvent.setup()
    conApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: pagina() },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(await screen.findByText('github.com')).toBeInTheDocument()
    expect(screen.getByText('(12.82 ms)')).toBeInTheDocument()
    expect(screen.getByText('A 140.82.121.3')).toBeInTheDocument()
  })

  it('una respuesta sin datos deja el contador en «0 logs»', async () => {
    const user = userEvent.setup()
    conApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: pagina({ entries: [], totalEntries: 0 }) },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(await screen.findAllByText('0 logs')).toHaveLength(2)
  })

  it('la raíz se escribe con un punto y los campos nulos quedan en blanco', async () => {
    const user = userEvent.setup()
    conApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: {
        response: pagina({
          entries: [
            {
              ...ENTRADA,
              rowNumber: 1,
              qname: '',
              qtype: null,
              qclass: null,
              answer: null,
              responseRtt: undefined,
            },
          ],
        }),
      },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    const fila = within(await screen.findByRole('row', { name: /127\.0\.0\.1/ }))
    expect(fila.getByText('.')).toBeInTheDocument()
    // Sin `responseRtt` no se pinta el paréntesis con los milisegundos.
    expect(screen.queryByText(/ ms\)/)).not.toBeInTheDocument()
  })

  it('«Last» se pide con pageNumber -1, que es como upstream llega a la última', async () => {
    const user = userEvent.setup()
    conApps([APP])
    const spy = vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: pagina({ pageNumber: 1, totalPages: 5, totalEntries: 100 }) },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))
    await screen.findByText('github.com')

    await user.click(screen.getByRole('button', { name: 'Last' }))

    expect(spy.mock.calls.at(-1)![1].pageNumber).toBe('-1')
  })

  it('un error del servidor sale como aviso y no borra la tabla anterior', async () => {
    const user = userEvent.setup()
    conApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'error',
      message: "Requested value 'ZZZ' was not found.",
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(await screen.findByText("Requested value 'ZZZ' was not found.")).toBeInTheDocument()
  })
})

describe('Query Logs — piezas puras', () => {
  it('el contador replica el formato de upstream', () => {
    expect(
      textoEstado({
        pageNumber: 2,
        totalPages: 5,
        totalEntries: 48312,
        entries: [
          { ...ENTRADA, rowNumber: 26 },
          { ...ENTRADA, rowNumber: 50 },
        ],
      }),
    ).toBe('26-50 (2) of 48312 logs (page 2 of 5)')
    expect(textoEstado({ pageNumber: 1, totalPages: 0, totalEntries: 0, entries: [] })).toBe(
      '0 logs',
    )
  })

  it('la ventana de páginas es de diez, centrada en la actual', () => {
    expect(rangoPaginas(1, 3)).toEqual([1, 2, 3])
    expect(rangoPaginas(1, 100)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    expect(rangoPaginas(20, 100)).toEqual([15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
    // Al final, la ventana se desplaza hacia atrás para seguir siendo de diez.
    expect(rangoPaginas(100, 100)).toEqual([91, 92, 93, 94, 95, 96, 97, 98, 99, 100])
  })

  it('el color de fila lo decide el RCODE y, dentro de él, el tipo de respuesta', () => {
    const c = (rcode: string, responseType: string) =>
      claseFila({ ...ENTRADA, rcode, responseType })

    expect(c('ServerFailure', 'Recursive')).not.toBe('')
    expect(c('NxDomain', 'Blocked')).toBe(c('NoError', 'UpstreamBlockedCached'))
    expect(c('NxDomain', 'Authoritative')).not.toBe(c('NxDomain', 'Blocked'))
    expect(c('NoError', 'Authoritative')).not.toBe(c('NoError', 'Recursive'))
    expect(c('NoError', 'Loquesea')).toBe('')
  })
})
