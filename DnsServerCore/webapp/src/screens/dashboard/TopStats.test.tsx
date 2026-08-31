import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from '../../api/dashboard'
import * as client from '../../api/client'
import { TopStats } from './TopStats'
import { Dashboard } from './Dashboard'

afterEach(() => vi.restoreAllMocks())

const CLIENTES = [
  { name: '10.0.0.1', domain: 'pc.casa.test', hits: 1234, rateLimited: false },
  { name: '10.0.0.9', domain: '', hits: 99, rateLimited: true },
]

function servidorTop(respuesta: Record<string, unknown>) {
  return vi.spyOn(client, 'apiRequest').mockResolvedValue({
    kind: 'ok',
    data: { status: 'ok', response: respuesta },
  } as never)
}

describe('modal Top Stats', () => {
  it('cerrado no pide nada al servidor', () => {
    const spy = servidorTop({ topClients: [] })
    render(<TopStats tipo={null} rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(spy).not.toHaveBeenCalled()
  })

  it('el título lleva el límite dentro, como en upstream', async () => {
    servidorTop({ topClients: CLIENTES })
    render(<TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(await screen.findByText('Top 1000 Clients')).toBeTruthy()
  })

  it('pide getTop con el rango, el tipo y el límite de 1000', async () => {
    const spy = servidorTop({ topDomains: [] })
    render(<TopStats tipo="TopDomains" rango="LastWeek" token="t" onCerrar={() => {}} />)
    await waitFor(() => {
      const call = spy.mock.calls.find((c) => c[0] === 'dashboard/stats/getTop')
      expect(call![1]?.body).toMatchObject({
        type: 'LastWeek',
        statsType: 'TopDomains',
        limit: '1000',
      })
    })
  })

  it('un cliente enseña su dominio debajo del nombre', async () => {
    servidorTop({ topClients: CLIENTES })
    render(<TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(await screen.findByText('pc.casa.test')).toBeTruthy()
  })

  it('un cliente sin dominio se pinta como la raíz', async () => {
    servidorTop({ topClients: CLIENTES })
    render(<TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />)
    await screen.findByText('pc.casa.test')
    expect(screen.getByText('.')).toBeTruthy()
  })

  it('un cliente limitado lo dice detrás del nombre', async () => {
    servidorTop({ topClients: CLIENTES })
    render(<TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(await screen.findByText(/10\.0\.0\.9 \(rate limited\)/)).toBeTruthy()
  })

  it('un dominio NO enseña la línea del dominio: ese campo es sólo de clientes', async () => {
    servidorTop({ topDomains: [{ name: 'github.com', hits: 7 }] })
    render(<TopStats tipo="TopDomains" rango="LastHour" token="t" onCerrar={() => {}} />)
    await screen.findByText('github.com')
    expect(screen.queryByText('.')).toBeNull()
  })

  it('la cabecera cambia entre Client/Queries y Domain/Hits', async () => {
    servidorTop({ topClients: CLIENTES })
    const { unmount } = render(
      <TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />,
    )
    expect(await screen.findByText('Client')).toBeTruthy()
    expect(screen.getByText('Queries')).toBeTruthy()
    unmount()

    servidorTop({ topDomains: [{ name: 'a.test', hits: 1 }] })
    render(<TopStats tipo="TopDomains" rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(await screen.findByText('Domain')).toBeTruthy()
    expect(screen.getByText('Hits')).toBeTruthy()
  })

  it('sin datos dice «No Data», con el texto de upstream', async () => {
    servidorTop({ topClients: [] })
    render(<TopStats tipo="TopClients" rango="LastHour" token="t" onCerrar={() => {}} />)
    expect(await screen.findByText('No Data')).toBeTruthy()
  })
})

describe('los tres botones «More» del Dashboard', () => {
  const grafica = { labels: ['a', 'b'], datasets: [{ label: 'Total', data: [1, 2] }] }
  const DATOS = {
    stats: {
      totalQueries: 10, totalNoError: 10, totalServerFailure: 0, totalNxDomain: 0,
      totalRefused: 0, totalAuthoritative: 0, totalRecursive: 10, totalCached: 0,
      totalBlocked: 0, totalDropped: 0, totalClients: 2,
      zones: 1, cachedEntries: 0, allowedZones: 0, blockedZones: 0,
      allowListZones: 0, blockListZones: 0,
    },
    mainChartData: grafica,
    queryResponseChartData: grafica,
    queryTypeChartData: grafica,
    protocolTypeChartData: grafica,
    topClients: CLIENTES,
    topDomains: [],
    topBlockedDomains: [],
  }

  it('«More» de Top Clients abre el modal y pide TopClients', async () => {
    // Before phase 10 the three buttons were in place and did nothing.
    const usuario = userEvent.setup()
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: DATOS } as never)
    const top = vi.spyOn(api, 'getTop').mockResolvedValue(CLIENTES as never)
    render(<Dashboard token="t" />)

    const panel = (await screen.findByText('Top Clients')).closest('div')!.parentElement!
    await usuario.click(within(panel).getByRole('button', { name: 'More' }))

    expect(await screen.findByText('Top 1000 Clients')).toBeTruthy()
    await waitFor(() => expect(top).toHaveBeenCalledWith('t', 'LastHour', 'TopClients', 1000))
  })

  it('la lista corta de clientes ya enseña el dominio y el marcado de limitado', async () => {
    vi.spyOn(api, 'getDashboardStats').mockResolvedValue({ kind: 'ok', data: DATOS } as never)
    render(<Dashboard token="t" />)
    expect(await screen.findByText('pc.casa.test')).toBeTruthy()
    expect(screen.getByText(/10\.0\.0\.9 \(rate limited\)/)).toBeTruthy()
  })
})
