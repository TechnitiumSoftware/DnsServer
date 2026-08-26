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
  it('redondea a un decimal como upstream', () => {
    expect(porcentaje(41008, 48312)).toBe('84,9%')
    expect(porcentaje(36, 48312)).toBe('0,1%')
  })
  it('no divide por cero', () => {
    expect(porcentaje(0, 0)).toBe('0%')
  })
})

describe('Dashboard', () => {
  it('pinta las once métricas con sus etiquetas literales', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    // «Blocked» y «Cache» salen también como contador del servidor, así que se
    // busca dentro de las tarjetas de métrica, no en toda la pantalla.
    const tiles = within(await screen.findByTestId('metricas'))
    for (const l of ['Total Queries','No Error','Server Failure','NX Domain','Refused','Authoritative','Recursive','Cached','Blocked','Dropped','Clients']) {
      expect(tiles.getByText(l)).toBeInTheDocument()
    }
    expect(tiles.getByText('48.312')).toBeInTheDocument()
    expect(tiles.getByText('84,9%')).toBeInTheDocument()
  })

  it('pinta los seis contadores del servidor', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    const c = within(await screen.findByTestId('contadores'))
    for (const l of ['Zones','Cache','Allowed','Blocked','Allow List','Block List']) {
      expect(c.getByText(l)).toBeInTheDocument()
    }
    expect(c.getByText('184.302')).toBeInTheDocument()
  })

  it('ofrece los seis rangos con sus etiquetas y arranca en Last Hour', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    const b = await screen.findByRole('button', { name: 'Last Hour' })
    expect(b).toHaveAttribute('aria-pressed', 'true')
    for (const l of ['Last Day','Last Week','Last Month','Last Year','Custom']) {
      expect(screen.getByRole('button', { name: l })).toHaveAttribute('aria-pressed', 'false')
    }
  })

  it('cambiar de rango vuelve a pedir los datos con ese tipo', async () => {
    const spy = vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    await screen.findByText('Total Queries')
    spy.mockClear()
    await userEvent.click(screen.getByRole('button', { name: 'Last Week' }))
    expect(spy.mock.calls[0][1]).toBe('LastWeek')
  })

  it('pinta las CUATRO gráficas, no dos', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByLabelText('Consultas por periodo')).toBeInTheDocument()
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
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(datos as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByText('No data for this period.')).toBeInTheDocument()
  })

  it('si la llamada falla, la pantalla no revienta', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue(null)
    render(<Dashboard token="t" />)
    expect(await screen.findByText('Total Queries')).toBeInTheDocument()
    // sin datos, los valores salen como raya en vez de romper
    expect(within(screen.getByTestId('metricas')).getAllByText('—').length).toBe(11)
  })
})
