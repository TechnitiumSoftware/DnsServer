import { useEffect, useState } from 'react'
import {
  ETIQUETA_RANGO, RANGOS, getDashboardStats,
  type DashboardStats, type Rango, type Stats, type TopEntry,
} from '../../api/dashboard'
import { Chart } from './Chart'
import type { ChartData } from '../../api/dashboard'
import styles from './Dashboard.module.css'

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

const num = (n: number) => n.toLocaleString('es-ES')

/** El porcentaje se calcula sobre el total, como en upstream. */
export function porcentaje(valor: number, total: number): string {
  if (total === 0) return '0%'
  return (Math.round((valor / total) * 1000) / 10).toLocaleString('es-ES') + '%'
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
          <div className={styles.vacio}>Sin datos en este periodo.</div>
        )}
      </div>
    </div>
  )
}

function Top({ titulo, filas, onMore }: { titulo: string; filas: TopEntry[]; onMore: () => void }) {
  return (
    <div className={styles.panel}>
      <div className={styles.ph}>
        <h2>{titulo}</h2>
        <button type="button" onClick={onMore}>More</button>
      </div>
      <div className={styles.pb} style={{ paddingTop: 4 }}>
        {filas.length === 0 && <div className={styles.vacio}>Sin datos en este periodo.</div>}
        {filas.slice(0, 5).map((f) => (
          <div className={styles.toprow} key={f.name}>
            <span className={styles.n}>{f.name}</span>
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
      <div className={styles.seg} role="group" aria-label="Periodo">
        {RANGOS.map((r) => (
          <button key={r} type="button" aria-pressed={r === rango} onClick={() => setRango(r)}>
            {ETIQUETA_RANGO[r]}
          </button>
        ))}
      </div>

      <div className={styles.tiles} data-testid="metricas">
        {METRICAS.map((m) => (
          <div className={styles.tile} key={m.k} style={{ ['--tc' as string]: m.color }}>
            <div className="v">{s ? num(s[m.k]) : '—'}</div>
            <div className="p">{m.pct && s ? porcentaje(s[m.k], total) : ' '}</div>
            <div className="k">{m.label}</div>
          </div>
        ))}
      </div>

      <div className={styles.grid}>
        <div className={styles.col}>
          <div className={styles.panel}>
            <div className={styles.ph}><h2>Queries</h2></div>
            <div className={styles.pb}>
              {cargando && <div className={styles.vacio}>Cargando…</div>}
              {!cargando && datos && tieneDatos(datos.mainChartData) && (
                <Chart tipo="line" data={datos.mainChartData} aria="Consultas por periodo" />
              )}
              {!cargando && (!datos || !tieneDatos(datos.mainChartData)) && (
                <div className={styles.vacio}>Sin consultas en este periodo.</div>
              )}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <Top titulo="Top Domains" filas={datos?.topDomains ?? []} onMore={() => {}} />
            <Top titulo="Top Blocked Domains" filas={datos?.topBlockedDomains ?? []} onMore={() => {}} />
          </div>
        </div>

        <div className={styles.col}>
          <div className={styles.panel}>
            <div className={styles.ph}><h2>Server</h2></div>
            <div className={styles.pb}>
              <div className={styles.counters} data-testid="contadores">
                {CONTADORES.map((c) => (
                  <div className={styles.cnt} key={c.k}>
                    <div className="v">{s ? num(s[c.k]) : '—'}</div>
                    <div className="k">{c.label}</div>
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
          <Top titulo="Top Clients" filas={datos?.topClients ?? []} onMore={() => {}} />
        </div>
      </div>
    </>
  )
}
