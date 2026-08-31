import { useEffect, useState, type ReactNode } from 'react'
import {
  ETIQUETA_RANGO, RANGOS, getDashboardStats,
  type DashboardStats, type Rango, type Stats, type TipoTop, type TopEntry,
} from '../../api/dashboard'
import { Chart } from './Chart'
import { TopStats } from './TopStats'
import type { ChartData } from '../../api/dashboard'
import { SectionHeader } from '../../ui/SectionHeader'
import {Empty, Loading} from '../../ui/Empty'
import styles from './Dashboard.module.css'
import { Cuerpo, Panel } from '../../ui/Panel'
import { Button } from '../../ui/Button'
import { type AlertType } from '../../ui/Alert'
import { MenuBloqueo } from './MenuBloqueo'
import { instantesDelRango, loQueFalta } from './rango-personalizado'
import { Segmentado } from '../../ui/Segmentado'
import { avisoDeFallo } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'

/*
The eleven metrics, in upstream's order and with its literal labels. Each one's
colour is that of its series in the main chart.
*/
const METRICAS: { k: keyof Stats; label: string; color: string; pct?: boolean }[] = [
  /*
  The total carries no percentage. Upstream writes a fixed "100%" there in the
  markup —`main.js` never updates it— which is decoration: the percentage of a
  total over itself says nothing. Really calculated, with the server freshly
  started it came out as "0%" under "Total Queries", which on top of informing
  nothing is confusing. The rule that stands is the one the clients tile already
  followed: the percentage is the share of the query total, and the total has no
  share of itself.
  */
  { k: 'totalQueries', label: 'Total Queries', color: '#60a5fa' },
  { k: 'totalNoError', label: 'No Error', color: '#34d399', pct: true },
  { k: 'totalServerFailure', label: 'Server Failure', color: '#f87171', pct: true },
  { k: 'totalNxDomain', label: 'NX Domain', color: '#8b95a7', pct: true },
  { k: 'totalRefused', label: 'Refused', color: '#22d3ee', pct: true },
  { k: 'totalAuthoritative', label: 'Authoritative', color: '#a3a132', pct: true },
  { k: 'totalRecursive', label: 'Recursive', color: '#2dd4bf', pct: true },
  { k: 'totalCached', label: 'Cached', color: '#a78bfa', pct: true },
  { k: 'totalBlocked', label: 'Blocked', color: '#f5a524', pct: true },
  { k: 'totalDropped', label: 'Dropped', color: '#5d6779', pct: true },
  { k: 'totalClients', label: 'Clients', color: '#e6e9ef' },
]

const CONTADORES: { k: keyof Stats; label: string }[] = [
  { k: 'zones', label: 'Zones' },
  { k: 'cachedEntries', label: 'Cache' },
  { k: 'allowedZones', label: 'Allowed' },
  { k: 'blockedZones', label: 'Blocked' },
  { k: 'allowListZones', label: 'Allow List' },
  { k: 'blockListZones', label: 'Block List' },
]

/*
The numbers come out as in upstream, and upstream does NOT pin a locale: it uses
a bare `toLocaleString()` (main.js:2632-2650), that is, the browser's. They were
nailed to `es-ES`, so a server in English showed "84.930" as "84.930" but with
the dot meaning the opposite.
*/
const num = (n: number) => n.toLocaleString()

/*
The percentage carries no locale, neither in upstream nor here: it is
`toFixed(2)`, which always writes the dot (main.js:2652-2676). And with zero
queries it is a literal "0%", not "0.00%".
*/
export function porcentaje(valor: number, total: number): string {
  if (total === 0) return '0%'
  return ((valor * 100) / total).toFixed(2) + '%'
}

/** A chart with no value other than zero is not drawn: an empty canvas takes up
 *  the same room and says nothing. It says there is no data instead. */
export function tieneDatos(d?: { datasets?: { data: number[] }[] }): boolean {
  if (!d?.datasets?.length) return false
  return d.datasets.some((s) => (s.data ?? []).some((n) => Number(n) > 0))
}

function Reparto({ titulo, data }: { titulo: string; data: ChartData }) {
  return (
    <Panel titulo={titulo} className={styles.panel}>
      <Cuerpo>
        {tieneDatos(data) ? (
          <Chart tipo="doughnut" data={data} alto={190} aria={titulo} />
        ) : (
          <Empty compacto>No data for this period.</Empty>
        )}
      </Cuerpo>
    </Panel>
  )
}

function Top({
  titulo,
  filas,
  esCliente = false,
  onMore,
  antesDeMore,
}: {
  titulo: string
  filas: TopEntry[]
  /** A client also shows the domain it resolved and whether it was rate limited. */
  esCliente?: boolean
  onMore: () => void
  /** The panel's own action, to the left of "More". Only the blocked-domains one
   *  uses it, with the blocking menu upstream puts there. */
  antesDeMore?: ReactNode
}) {
  return (
    <Panel
      titulo={titulo}
      className={styles.panel}
      acciones={
        <div className={styles.accionesPanel}>
          {antesDeMore}
          {/* It was a bare `<button>`, with no class: the browser drew it with
              its default style, in the middle of a console with a system of its
              own. */}
          <Button size="sm" onClick={onMore}>
            More
          </Button>
        </div>
      }
    >
      <Cuerpo className={styles.pbAjustado}>
        {filas.length === 0 && <Empty compacto>No data for this period.</Empty>}
        {filas.slice(0, 5).map((f, i) => (
          <div
            className={`${styles.toprow}${f.rateLimited ? ` ${styles.limitada}` : ''}`}
            key={`${f.name}|${i}`}
          >
            <span className={styles.n}>
              {f.name}
              {f.rateLimited ? ' (rate limited)' : ''}
              {esCliente && (
                <span className={styles.topDominio}>
                  {f.domain === '' || f.domain == null ? '.' : f.domain}
                </span>
              )}
            </span>
            <span className={styles.c}>{num(f.hits)}</span>
          </div>
        ))}
      </Cuerpo>
    </Panel>
  )
}

export function Dashboard({ token }: { token: string | null }) {
  const [rango, setRango] = useState<Rango>('LastHour')
  const [datos, setDatos] = useState<DashboardStats | null>(null)
  const [cargando, setCargando] = useState(true)
  const [top, setTop] = useState<TipoTop | null>(null)
  const [aviso, setAviso] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  /*
  The custom range. `inicio`/`fin` are what is typed into the two fields;
  `pedido` is the last thing "Show" was pressed with, which is what triggers the
  query. They are kept apart because typing a date must not reload the Dashboard:
  upstream does not either, it waits for the button (`main.js:646`).
  */
  const [inicio, setInicio] = useState('')
  const [fin, setFin] = useState('')
  const [pedido, setPedido] = useState<{ start: string; end: string } | null>(null)

  useEffect(() => {
    let cancelado = false
    // With "Custom" chosen and no dates yet there is nothing to ask for.
    if (rango === 'Custom' && pedido == null) {
      setCargando(false)
      return
    }
    setCargando(true)
    void (async () => {
      const r = await getDashboardStats(token, rango, pedido ?? undefined)
      if (cancelado) return
      setCargando(false)
      if (r.kind === 'ok') {
        setDatos(r.data)
        return
      }
      /*
      A failure is NOT drawn as a quiet server. Without this, the eleven tiles
      came out at zero and the panels said "No queries for this period.", which is
      exactly what a DNS that has received nothing shows: the screen was answering
      falsely about the one thing people come here to look at.
      */
      setDatos(null)
      setAviso(avisoDeFallo(r))
    })()
    return () => {
      cancelado = true
    }
  }, [token, rango, pedido])

  function mostrarRango() {
    const falta = loQueFalta(inicio, fin)
    if (falta != null) {
      setAviso({ type: 'warning', title: 'Missing!', text: falta })
      return
    }
    setAviso(null)
    setPedido(instantesDelRango(inicio, fin))
  }

  const s = datos?.stats
  const total = s?.totalQueries ?? 0

  return (
    <>
      <SectionHeader
        titulo="Dashboard"
        acciones={
          <Segmentado
            etiqueta="Period"
            opciones={RANGOS.map((r) => ({ id: r, etiqueta: ETIQUETA_RANGO[r] }))}
            activa={rango}
            onElegir={(r) => {
              setRango(r)
              if (r !== 'Custom') setPedido(null)
            }}
          />
        }
      />

      {rango === 'Custom' && (
        <div className={styles.rangoPropio}>
          <label>
            Start
            <input type="date" value={inicio} onChange={(e) => setInicio(e.target.value)} />
          </label>
          <label>
            End
            <input type="date" value={fin} onChange={(e) => setFin(e.target.value)} />
          </label>
          <Button size="sm" variant="primary" onClick={mostrarRango}>
            Show
          </Button>
        </div>
      )}

      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      <div className={styles.tiles} data-testid="metricas">
        {METRICAS.map((m) => (
          <div className={styles.tile} key={m.k} style={{ ['--tc' as string]: m.color }}>
            <div className={styles.v}>{s ? num(s[m.k]) : '—'}</div>
            <div className={styles.p}>{m.pct && s ? porcentaje(s[m.k], total) : ' '}</div>
            <div className={styles.k}>{m.label}</div>
          </div>
        ))}
      </div>

      <div className={styles.grid}>
        <div className={styles.col}>
          <Panel titulo="Queries" className={styles.panel}>
            <Cuerpo>
              {cargando && <Loading compacto />}
              {!cargando && datos && tieneDatos(datos.mainChartData) && (
                <Chart tipo="line" data={datos.mainChartData} aria="Queries over time" />
              )}
              {!cargando && (!datos || !tieneDatos(datos.mainChartData)) && (
                <Empty compacto>No queries for this period.</Empty>
              )}
            </Cuerpo>
          </Panel>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <Top
              titulo="Top Domains"
              filas={datos?.topDomains ?? []}
              onMore={() => setTop('TopDomains')}
            />
            <Top
              titulo="Top Blocked Domains"
              filas={datos?.topBlockedDomains ?? []}
              onMore={() => setTop('TopBlockedDomains')}
              antesDeMore={<MenuBloqueo token={token} onAviso={setAviso} />}
            />
          </div>
        </div>

        <div className={styles.col}>
          <Panel titulo="Server" className={styles.panel}>
            <Cuerpo>
              <div className={styles.counters} data-testid="contadores">
                {CONTADORES.map((c) => (
                  <div className={styles.cnt} key={c.k}>
                    <div className={styles.v}>{s ? num(s[c.k]) : '—'}</div>
                    <div className={styles.k}>{c.label}</div>
                  </div>
                ))}
              </div>
            </Cuerpo>
          </Panel>
          {datos && (
            <>
              <Reparto titulo="Query Response Types" data={datos.queryResponseChartData} />
              <Reparto titulo="Query Types" data={datos.queryTypeChartData} />
              <Reparto titulo="Protocol Types" data={datos.protocolTypeChartData} />
            </>
          )}
          <Top
            titulo="Top Clients"
            filas={datos?.topClients ?? []}
            esCliente
            onMore={() => setTop('TopClients')}
          />
        </div>
      </div>

      <TopStats tipo={top} rango={rango} token={token} onCerrar={() => setTop(null)} />
    </>
  )
}
