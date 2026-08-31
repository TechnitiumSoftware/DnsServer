import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Dashboard, porcentaje } from './Dashboard'
import * as api from '../../api/dashboard'

afterEach(() => vi.restoreAllMocks())

const grafica = { labels: ['a', 'b'], datasets: [{ label: 'Total', data: [1, 2] }] }
const vacia = { labels: ['a'], datasets: [{ label: 'Total', data: [0] }] }
const datos = {
  stats: {
    totalQueries: 48312, totalNoError: 41008, totalServerFailure: 36, totalNxDomain: 1204,
    totalRefused: 12, totalAuthoritative: 9517, totalRecursive: 7883, totalCached: 24860,
    totalBlocked: 6052, totalDropped: 0, totalClients: 27,
    zones: 14, cachedEntries: 8204, allowedZones: 3, blockedZones: 21,
    allowListZones: 0, blockListZones: 184302,
  },
  mainChartData: grafica, queryResponseChartData: grafica,
  queryTypeChartData: grafica, protocolTypeChartData: grafica,
  topClients: [{ name: '10.0.1.42', hits: 12408 }],
  topDomains: [{ name: 'github.com', hits: 3204 }],
  topBlockedDomains: [],
}

describe('porcentaje', () => {
  // main.js:2652-2676 — `toFixed(2)`, with a dot, no locale and two decimals.
  it('dos decimales y punto, como upstream', () => {
    expect(porcentaje(41008, 48312)).toBe('84.88%')
    expect(porcentaje(36, 48312)).toBe('0.07%')
  })
  it('sin consultas es «0%» literal, no «0.00%»', () => {
    expect(porcentaje(0, 0)).toBe('0%')
  })
})

describe('Dashboard', () => {
  it('pinta las once métricas con sus etiquetas literales', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    // "Blocked" and "Cache" also come out as server counters, so the search is
    // done inside the metric cards, not across the whole screen.
    const tiles = within(await screen.findByTestId('metricas'))
    for (const l of ['Total Queries','No Error','Server Failure','NX Domain','Refused','Authoritative','Recursive','Cached','Blocked','Dropped','Clients']) {
      expect(tiles.getByText(l)).toBeInTheDocument()
    }
    // The numbers go with the browser's locale because upstream does not pin one
    // either (main.js:2632). It is asserted this way so as not to nail the test to one.
    expect(tiles.getByText((48312).toLocaleString())).toBeInTheDocument()
    expect(tiles.getByText('84.88%')).toBeInTheDocument()
  })

  /*
  Upstream writes a fixed "100%" under "Total Queries" that its JavaScript never
  updates. Really calculated it gave "0%" with the server freshly started, which
  confuses more than it informs: the percentage is the share of the total, and the
  total has no share of itself.
  */
  it('la baldosa del total no lleva porcentaje, como la de clientes', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    const tiles = within(await screen.findByTestId('metricas'))
    expect(tiles.queryByText('100.00%')).not.toBeInTheDocument()
    expect(tiles.queryByText('100%')).not.toBeInTheDocument()
    // and the ones that do carry it still carry it
    expect(tiles.getByText('84.88%')).toBeInTheDocument()
  })

  it('pinta los seis contadores del servidor', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    const c = within(await screen.findByTestId('contadores'))
    for (const l of ['Zones','Cache','Allowed','Blocked','Allow List','Block List']) {
      expect(c.getByText(l)).toBeInTheDocument()
    }
    expect(c.getByText((184302).toLocaleString())).toBeInTheDocument()
  })

  it('ofrece los seis rangos con sus etiquetas y arranca en Last Hour', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    const b = await screen.findByRole('button', { name: 'Last Hour' })
    expect(b).toHaveAttribute('aria-pressed', 'true')
    for (const l of ['Last Day','Last Week','Last Month','Last Year','Custom']) {
      expect(screen.getByRole('button', { name: l })).toHaveAttribute('aria-pressed', 'false')
    }
  })

  it('cambiar de rango vuelve a pedir los datos con ese tipo', async () => {
    const spy = vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    await screen.findByText('Total Queries')
    spy.mockClear()
    await userEvent.click(screen.getByRole('button', { name: 'Last Week' }))
    expect(spy.mock.calls[0][1]).toBe('LastWeek')
  })

  it('pinta las CUATRO gráficas, no dos', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByLabelText('Queries over time')).toBeInTheDocument()
    expect(screen.getByLabelText('Query Response Types')).toBeInTheDocument()
    expect(screen.getByLabelText('Query Types')).toBeInTheDocument()
    expect(screen.getByLabelText('Protocol Types')).toBeInTheDocument()
  })

  it('una gráfica sin datos dice que no los hay en vez de dejar un lienzo vacío', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({
      ...datos, mainChartData: vacia, queryResponseChartData: vacia,
      queryTypeChartData: vacia, protocolTypeChartData: vacia,
    } as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByText('No queries for this period.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Query Types')).not.toBeInTheDocument()
  })

  it('una lista Top vacía lo dice en vez de quedarse en blanco', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: datos } as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByText('No data for this period.')).toBeInTheDocument()
  })

  /*
  This test settled for "it does not blow up", and not blowing up was exactly the
  problem: with the call fallen over the screen showed eleven zeros and "No
  queries for this period.", which is the same thing a DNS that has received
  nothing shows. Whoever administers a server and reads that concludes no traffic
  is reaching them.
  */
  it('si la llamada falla, lo DICE, y no se hace pasar por un servidor tranquilo', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'error', message: 'boom' })
    render(<Dashboard token="t" />)
    expect(await screen.findByText('boom')).toBeInTheDocument()
    // and the values come out as a dash, which is the honest thing: they are unknown
    expect(within(screen.getByTestId('metricas')).getAllByText('—').length).toBe(11)
  })

  it('una sesión caducada se dice con su propio texto', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'invalid-token' })
    render(<Dashboard token="t" />)
    expect(await screen.findByText('Invalid token or session expired.')).toBeInTheDocument()
  })
})
