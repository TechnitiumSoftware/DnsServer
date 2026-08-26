import { useEffect, useState } from 'react'
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
import { Button } from '../../ui/Button'

/*
Las once métricas, en el orden de upstream y con sus etiquetas literales.
El color de cada una es el de su serie en la gráfica principal.
*/
const METRICAS: { k: keyof Stats; label: string; color: string; pct?: boolean }[] = [
  { k: 'totalQueries', label: 'Total Queries', color: '#60a5fa', pct: true },
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
Los números salen como en upstream, y upstream NO fija locale: usa
`toLocaleString()` a secas (main.js:2632-2650), o sea la del navegador. Estaban
clavados a `es-ES`, así que un servidor en inglés enseñaba «84.930» como
«84.930» pero con el punto significando lo contrario.
*/
const num = (n: number) => n.toLocaleString()

/*
El porcentaje NO lleva locale ni en upstream ni aquí: es `toFixed(2)`, que
siempre escribe el punto (main.js:2652-2676). Y con cero consultas es «0%»
literal, no «0,00%».
*/
export function porcentaje(valor: number, total: number): string {
  if (total === 0) return '0%'
  return ((valor * 100) / total).toFixed(2) + '%'
}

/** Una gráfica sin ningún valor distinto de cero no se pinta: un canvas vacío
 *  ocupa el mismo sitio y no dice nada. Se dice que no hay datos. */
export function tieneDatos(d?: { datasets?: { data: number[] }[] }): boolean {
  if (!d?.datasets?.length) return false
  return d.datasets.some((s) => (s.data ?? []).some((n) => Number(n) > 0))
}

function Reparto({ titulo, data }: { titulo: string; data: ChartData }) {
  return (
    <div className={styles.panel}>
      <div className={styles.ph}><h2>{titulo}</h2></div>
      <div className={styles.pb}>
        {tieneDatos(data) ? (
          <Chart tipo="doughnut" data={data} alto={190} aria={titulo} />
        ) : (
          <Empty compacto>No data for this period.</Empty>
        )}
      </div>
    </div>
  )
}

function Top({
  titulo,
  filas,
  esCliente = false,
  onMore,
}: {
  titulo: string
  filas: TopEntry[]
  /** Un cliente enseña además el dominio que resolvió y si estaba limitado. */
  esCliente?: boolean
  onMore: () => void
}) {
  return (
    <div className={styles.panel}>
      <div className={styles.ph}>
        <h2>{titulo}</h2>
        {/* Era un `<button>` a pelo, sin clase: lo pintaba el navegador con su
            estilo por defecto, en medio de una consola con sistema propio. */}
        <Button size="sm" onClick={onMore}>
          More
        </Button>
      </div>
      <div className={`${styles.pb} ${styles.pbAjustado}`}>
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
      </div>
    </div>
  )
}

export function Dashboard({ token }: { token: string | null }) {
  const [rango, setRango] = useState<Rango>('LastHour')
  const [datos, setDatos] = useState<DashboardStats | null>(null)
  const [cargando, setCargando] = useState(true)
  const [top, setTop] = useState<TipoTop | null>(null)

  useEffect(() => {
    let cancelado = false
    setCargando(true)
    void (async () => {
      const d = await getDashboardStats(token, rango)
      if (!cancelado) {
        setDatos(d)
        setCargando(false)
      }
    })()
    return () => {
      cancelado = true
    }
  }, [token, rango])

  const s = datos?.stats
  const total = s?.totalQueries ?? 0

  return (
    <>
      <SectionHeader
        titulo="Dashboard"
        acciones={
          <div className={styles.seg} role="group" aria-label="Period">
        {RANGOS.map((r) => (
          <button key={r} type="button" aria-pressed={r === rango} onClick={() => setRango(r)}>
            {ETIQUETA_RANGO[r]}
          </button>
        ))}
          </div>
        }
      />

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
          <div className={styles.panel}>
            <div className={styles.ph}><h2>Queries</h2></div>
            <div className={styles.pb}>
              {cargando && <Loading compacto />}
              {!cargando && datos && tieneDatos(datos.mainChartData) && (
                <Chart tipo="line" data={datos.mainChartData} aria="Queries over time" />
              )}
              {!cargando && (!datos || !tieneDatos(datos.mainChartData)) && (
                <Empty compacto>No queries for this period.</Empty>
              )}
            </div>
          </div>
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
            />
          </div>
        </div>

        <div className={styles.col}>
          <div className={styles.panel}>
            <div className={styles.ph}><h2>Server</h2></div>
            <div className={styles.pb}>
              <div className={styles.counters} data-testid="contadores">
                {CONTADORES.map((c) => (
                  <div className={styles.cnt} key={c.k}>
                    <div className={styles.v}>{s ? num(s[c.k]) : '—'}</div>
                    <div className={styles.k}>{c.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
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
