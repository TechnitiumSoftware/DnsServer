import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Logs } from './Logs'
import * as api from '../../api/logs'
import * as dashboard from '../../api/dashboard'
import * as apps from '../../api/apps'
import type { InstalledApp } from '../../api/apps'
import type { QueryLogEntry, QueryLogPage } from '../../api/logs'
import { rowClass, pageRange, textoEstado } from './QueryLogs'
import { choose, optionsOf, valorDe } from '../../test/dropdown'

afterEach(() => vi.restoreAllMocks())

const OK = { kind: 'ok' as const, data: {} }

const FILES = [
  { fileName: '2026-08-26', size: '2.96 KB' },
  { fileName: '2026-08-25', size: '20.48 KB' },
]

const DETAIL = {
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
  dnsApps: [DETAIL],
}

const SIN_QUERY_LOGS: InstalledApp = {
  name: 'NO DATA',
  description: 'Returns NO DATA.',
  version: '5.0',
  dnsApps: [{ ...DETAIL, classPath: 'NoData.App', isQueryLogs: false }],
}

const ENTRY: QueryLogEntry = {
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

function page(partial: Partial<QueryLogPage> = {}): QueryLogPage {
  return { pageNumber: 1, totalPages: 1, totalEntries: 1, entries: [ENTRY], ...partial }
}

function withApps(list: InstalledApp[]) {
  return vi
    .spyOn(apps, 'listApps')
    .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: { apps: list } } } as never)
}

describe('Logs › View Logs', () => {
  it('it lists the files with their size and offers to delete them all', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
    render(<Logs token="t" sub="View Logs" />)

    expect(await screen.findByText('2026-08-26')).toBeInTheDocument()
    expect(screen.getByText('[20.48 KB]')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Logs' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Stats' })).toBeInTheDocument()
  })

  it('with no files it says \"No Log File Was Found\" and \"Delete All Logs\" disappears, but NOT \"Delete All Stats\"', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: [] })
    render(<Logs token="t" sub="View Logs" />)

    expect(await screen.findByText('No Log File Was Found')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete All Logs' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete All Stats' })).toBeInTheDocument()
  })

  it('opening a file asks for only the first 2 MB and draws it', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
    const spy = vi.spyOn(api, 'downloadLogText').mockResolvedValue('[2026-08-26] Logging started.')
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')

    await user.click(screen.getByText('2026-08-26'))

    expect(spy).toHaveBeenCalledWith('t', '2026-08-26', '')
    expect(await screen.findByText('[2026-08-26] Logging started.')).toBeInTheDocument()
  })

  it('\"Download\" asks for the whole file through a single-use token', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
    vi.spyOn(api, 'downloadLogText').mockResolvedValue('x')
    const spy = vi.spyOn(api, 'openLogDownload').mockResolvedValue({ ok: true })
    render(<Logs token="t" sub="View Logs" />)
    await screen.findByText('2026-08-26')
    await user.click(screen.getByText('2026-08-26'))
    await screen.findByText('x')

    await user.click(screen.getByRole('button', { name: 'Download' }))

    expect(spy).toHaveBeenCalledWith('t', '2026-08-26', '')
  })

  it('deleting a file confirms with its name and alerts with the literal text', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
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

  it('\"Delete All Logs\" confirms and alerts with \"Logs Deleted!\"', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
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

  it('\"Delete All Stats\" calls the DASHBOARD endpoint, not the logs one', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
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

  it('the two delete permissions are different and apply separately', async () => {
    vi.spyOn(api, 'listLogFiles').mockResolvedValue({ kind: 'ok', data: FILES })
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

describe('Logs › Query Logs — the form', () => {
  it('it only offers the apps that declare `isQueryLogs`', async () => {
    withApps([SIN_QUERY_LOGS, APP])
    render(<Logs token="t" sub="Query Logs" />)

    const user = userEvent.setup()
    const appName = await screen.findByLabelText('App Name')
    expect(await optionsOf(user, appName)).toEqual(['Query Logs (Sqlite)'])
    expect(valorDe(appName)).toBe('Query Logs (Sqlite)')
    expect(valorDe(screen.getByLabelText('Class Path'))).toBe('QueryLogsSqlite.App')
  })

  it('the default values are those of the upstream form, not the server ones', async () => {
    withApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    expect(screen.getByLabelText('Page Number')).toHaveValue(1)
    expect(valorDe(screen.getByLabelText('Logs Per Page'))).toBe('10')
    expect(valorDe(screen.getByLabelText('Order'))).toBe('Descending')
    expect(screen.getByLabelText('From')).toHaveValue('')
    expect(screen.getByLabelText('Domain')).toHaveValue('')
  })

  it('\"Logs Per Page\" is remembered in localStorage under the upstream key', async () => {
    const user = userEvent.setup()
    withApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await choose(user, screen.getByLabelText('Logs Per Page'), '100')

    expect(localStorage.getItem('optQueryLogsEntriesPerPage')).toBe('100')
    localStorage.removeItem('optQueryLogsEntriesPerPage')
  })

  it('\"Query\" sends the fourteen filters with the form values', async () => {
    const user = userEvent.setup()
    withApps([APP])
    const spy = vi
      .spyOn(api, 'queryLogs')
      .mockResolvedValue({ kind: 'ok', data: { response: page() } } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.type(screen.getByLabelText('Domain'), 'casa.test')
    await choose(user, screen.getByLabelText('Protocol'), 'UDP')
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

  it('with no query-logs app, \"Query\" alerts with the text that points at Apps', async () => {
    const user = userEvent.setup()
    withApps([SIN_QUERY_LOGS])
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

  it('\"Export\" alerts with the SAME title but WITHOUT \"from the Apps section.\"', async () => {
    const user = userEvent.setup()
    withApps([SIN_QUERY_LOGS])
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

  it('\"Export\" with a valid app calls the export endpoint', async () => {
    const user = userEvent.setup()
    withApps([APP])
    const spy = vi.spyOn(api, 'exportLogsCsv').mockResolvedValue({ ok: true })
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.click(screen.getByRole('button', { name: 'Export' }))

    expect(spy.mock.calls[0][1]).toMatchObject({
      name: 'Query Logs (Sqlite)',
      classPath: 'QueryLogsSqlite.App',
    })
  })

  it('\"Reset\" returns the form to its default values', async () => {
    const user = userEvent.setup()
    withApps([APP])
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await user.type(screen.getByLabelText('Domain'), 'casa.test')
    await choose(user, screen.getByLabelText('Order'), 'Ascending')
    await user.click(screen.getByRole('button', { name: 'Reset' }))

    expect(screen.getByLabelText('Domain')).toHaveValue('')
    expect(valorDe(screen.getByLabelText('Order'))).toBe('Descending')
  })

  it('\"Live Update\" pins page and order, empties the range and disables those four controls', async () => {
    const user = userEvent.setup()
    withApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: page() },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')

    await choose(user, screen.getByLabelText('Order'), 'Ascending')
    await user.type(screen.getByLabelText('From'), '2026-08-25T00:00')
    await user.click(screen.getByLabelText('Live Update'))

    expect(valorDe(screen.getByLabelText('Order'))).toBe('Descending')
    expect(screen.getByLabelText('From')).toHaveValue('')
    expect(screen.getByLabelText('Page Number')).toBeDisabled()
    expect(screen.getByLabelText('Order')).toBeDisabled()
    expect(screen.getByLabelText('From')).toBeDisabled()
    expect(screen.getByLabelText('To')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Query' })).toBeDisabled()
  })

  it('\"Live Update\" queries again every 2 s, and stopping cuts it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const user = userEvent.setup({ delay: null })
      withApps([APP])
      const spy = vi.spyOn(api, 'queryLogs').mockResolvedValue({
        kind: 'ok',
        data: { response: page() },
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

describe('Logs › Query Logs — the table', () => {
  it('it draws one row per entry, with the RTT and the formatted timestamp', async () => {
    const user = userEvent.setup()
    withApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: page() },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(await screen.findByText('github.com')).toBeInTheDocument()
    expect(screen.getByText('(12.82 ms)')).toBeInTheDocument()
    expect(screen.getByText('A 140.82.121.3')).toBeInTheDocument()
  })

  it('a response with no data leaves the counter at \"0 logs\"', async () => {
    const user = userEvent.setup()
    withApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: page({ entries: [], totalEntries: 0 }) },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))

    expect(await screen.findAllByText('0 logs')).toHaveLength(2)
  })

  it('the root is written with a dot and the null fields are left blank', async () => {
    const user = userEvent.setup()
    withApps([APP])
    vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: {
        response: page({
          entries: [
            {
              ...ENTRY,
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

    const row = within(await screen.findByRole('row', { name: /127\.0\.0\.1/ }))
    expect(row.getByText('.')).toBeInTheDocument()
    // Without `responseRtt` the bracket with the milliseconds is not drawn.
    expect(screen.queryByText(/ ms\)/)).not.toBeInTheDocument()
  })

  it('\"Last\" is asked for with pageNumber -1, which is how upstream reaches the last', async () => {
    const user = userEvent.setup()
    withApps([APP])
    const spy = vi.spyOn(api, 'queryLogs').mockResolvedValue({
      kind: 'ok',
      data: { response: page({ pageNumber: 1, totalPages: 5, totalEntries: 100 }) },
    } as never)
    render(<Logs token="t" sub="Query Logs" />)
    await screen.findByLabelText('App Name')
    await user.click(screen.getByRole('button', { name: 'Query' }))
    await screen.findByText('github.com')

    await user.click(screen.getByRole('button', { name: 'Last' }))

    expect(spy.mock.calls.at(-1)![1].pageNumber).toBe('-1')
  })

  it('a server error comes out as an alert and does not wipe the previous table', async () => {
    const user = userEvent.setup()
    withApps([APP])
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
  it('the counter replicates the upstream format', () => {
    expect(
      textoEstado({
        pageNumber: 2,
        totalPages: 5,
        totalEntries: 48312,
        entries: [
          { ...ENTRY, rowNumber: 26 },
          { ...ENTRY, rowNumber: 50 },
        ],
      }),
    ).toBe('26-50 (2) of 48312 logs (page 2 of 5)')
    expect(textoEstado({ pageNumber: 1, totalPages: 0, totalEntries: 0, entries: [] })).toBe(
      '0 logs',
    )
  })

  it('the page window is ten wide, centred on the current one', () => {
    expect(pageRange(1, 3)).toEqual([1, 2, 3])
    expect(pageRange(1, 100)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    expect(pageRange(20, 100)).toEqual([15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
    // At the end, the window slides backwards so it keeps being ten wide.
    expect(pageRange(100, 100)).toEqual([91, 92, 93, 94, 95, 96, 97, 98, 99, 100])
  })

  it('the row colour is decided by the RCODE and, within it, the response type', () => {
    const c = (rcode: string, responseType: string) =>
      rowClass({ ...ENTRY, rcode, responseType })

    expect(c('ServerFailure', 'Recursive')).not.toBe('')
    expect(c('NxDomain', 'Blocked')).toBe(c('NoError', 'UpstreamBlockedCached'))
    expect(c('NxDomain', 'Authoritative')).not.toBe(c('NxDomain', 'Blocked'))
    expect(c('NoError', 'Authoritative')).not.toBe(c('NoError', 'Recursive'))
    expect(c('NoError', 'Loquesea')).toBe('')
  })
})
