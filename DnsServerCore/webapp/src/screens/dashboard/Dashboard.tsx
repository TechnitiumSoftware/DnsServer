import { useEffect, useState, type ReactNode } from 'react'
import {
  RANGE_LABEL, RANGES, getDashboardStats,
  type DashboardStats, type Range, type Stats, type TopKind, type TopEntry,
} from '../../api/dashboard'
import { Chart } from './Chart'
import { TopStats } from './TopStats'
import type { ChartData } from '../../api/dashboard'
import { SectionHeader } from '../../ui/SectionHeader'
import {Empty, Loading} from '../../ui/Empty'
import styles from './Dashboard.module.css'
import { Body, Panel } from '../../ui/Panel'
import { Button } from '../../ui/Button'
import { type AlertType } from '../../ui/Alert'
import { BlockingMenu } from './BlockingMenu'
import { rangeInstants, loQueFalta } from './custom-range'
import { Segmented } from '../../ui/Segmented'
import { noticeFromFailure } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

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

const COUNTERS: { k: keyof Stats; label: string }[] = [
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
const num2 = (n: number) => n.toLocaleString()

/*
The percentage carries no locale, neither in upstream nor here: it is
`toFixed(2)`, which always writes the dot (main.js:2652-2676). And with zero
queries it is a literal "0%", not "0.00%".
*/
export function percentage(value: number, total: number): string {
  if (total === 0) return '0%'
  return ((value * 100) / total).toFixed(2) + '%'
}

/** A chart with no value other than zero is not drawn: an empty canvas takes up
 *  the same room and says nothing. It says there is no data instead. */
export function hasData(d?: { datasets?: { data: number[] }[] }): boolean {
  if (!d?.datasets?.length) return false
  return d.datasets.some((s) => (s.data ?? []).some((n) => Number(n) > 0))
}

function Split({ title, data }: { title: string; data: ChartData }) {
  return (
    <Panel title={title} className={styles.panel}>
      <Body>
        {hasData(data) ? (
          <Chart type="doughnut" data={data} height={190} aria={title} />
        ) : (
          <Empty compacto>No data for this period.</Empty>
        )}
      </Body>
    </Panel>
  )
}

function Top({
  title,
  rows,
  isClient = false,
  onMore,
  antesDeMore,
}: {
  title: string
  rows: TopEntry[]
  /** A client also shows the domain it resolved and whether it was rate limited. */
  isClient?: boolean
  onMore: () => void
  /** The panel's own action, to the left of "More". Only the blocked-domains one
   *  uses it, with the blocking menu upstream puts there. */
  antesDeMore?: ReactNode
}) {
  return (
    <Panel
      title={title}
      className={styles.panel}
      actions={
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
      <Body className={styles.pbAdjusted}>
        {rows.length === 0 && <Empty compacto>No data for this period.</Empty>}
        {rows.slice(0, 5).map((f, i) => (
          <div
            className={`${styles.toprow}${f.rateLimited ? ` ${styles.limited}` : ''}`}
            key={`${f.name}|${i}`}
          >
            <span className={styles.n}>
              {f.name}
              {f.rateLimited ? ' (rate limited)' : ''}
              {isClient && (
                <span className={styles.topDomain}>
                  {f.domain === '' || f.domain == null ? '.' : f.domain}
                </span>
              )}
            </span>
            <span className={styles.c}>{num2(f.hits)}</span>
          </div>
        ))}
      </Body>
    </Panel>
  )
}

export function Dashboard({ token }: { token: string | null }) {
  const [range, setRango] = useState<Range>('LastHour')
  const [data, setDatos] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [top, setTop] = useState<TopKind | null>(null)
  const [notice, setNotice] = useState<{ type: AlertType; title: string; text: string } | null>(null)
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
    let cancelled = false
    // With "Custom" chosen and no dates yet there is nothing to ask for.
    if (range === 'Custom' && pedido == null) {
      setLoading(false)
      return
    }
    setLoading(true)
    void (async () => {
      const r = await getDashboardStats(token, range, pedido ?? undefined)
      if (cancelled) return
      setLoading(false)
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
      setNotice(noticeFromFailure(r))
    })()
    return () => {
      cancelled = true
    }
  }, [token, range, pedido])

  function showRange() {
    const missing = loQueFalta(inicio, fin)
    if (missing != null) {
      setNotice({ type: 'warning', title: 'Missing!', text: missing })
      return
    }
    setNotice(null)
    setPedido(rangeInstants(inicio, fin))
  }

  const s = data?.stats
  const total = s?.totalQueries ?? 0

  return (
    <>
      <SectionHeader
        title="Dashboard"
        actions={
          <Segmented
            label="Period"
            options={RANGES.map((r) => ({ id: r, label: RANGE_LABEL[r] }))}
            active={range}
            onChoose={(r) => {
              setRango(r)
              if (r !== 'Custom') setPedido(null)
            }}
          />
        }
      />

      {range === 'Custom' && (
        <div className={styles.ownRange}>
          <label>
            Start
            <input type="date" value={inicio} onChange={(e) => setInicio(e.target.value)} />
          </label>
          <label>
            End
            <input type="date" value={fin} onChange={(e) => setFin(e.target.value)} />
          </label>
          <Button size="sm" variant="primary" onClick={showRange}>
            Show
          </Button>
        </div>
      )}

      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.tiles} data-testid="metricas">
        {METRICAS.map((m) => (
          <div className={styles.tile} key={m.k} style={{ ['--tc' as string]: m.color }}>
            <div className={styles.v}>{s ? num2(s[m.k]) : '—'}</div>
            <div className={styles.p}>{m.pct && s ? percentage(s[m.k], total) : ' '}</div>
            <div className={styles.k}>{m.label}</div>
          </div>
        ))}
      </div>

      <div className={styles.grid}>
        <div className={styles.col}>
          <Panel title="Queries" className={styles.panel}>
            <Body>
              {loading && <Loading compacto />}
              {!loading && data && hasData(data.mainChartData) && (
                <Chart type="line" data={data.mainChartData} aria="Queries over time" />
              )}
              {!loading && (!data || !hasData(data.mainChartData)) && (
                <Empty compacto>No queries for this period.</Empty>
              )}
            </Body>
          </Panel>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <Top
              title="Top Domains"
              rows={data?.topDomains ?? []}
              onMore={() => setTop('TopDomains')}
            />
            <Top
              title="Top Blocked Domains"
              rows={data?.topBlockedDomains ?? []}
              onMore={() => setTop('TopBlockedDomains')}
              antesDeMore={<BlockingMenu token={token} onNotice={setNotice} />}
            />
          </div>
        </div>

        <div className={styles.col}>
          <Panel title="Server" className={styles.panel}>
            <Body>
              <div className={styles.counters} data-testid="contadores">
                {COUNTERS.map((c) => (
                  <div className={styles.cnt} key={c.k}>
                    <div className={styles.v}>{s ? num2(s[c.k]) : '—'}</div>
                    <div className={styles.k}>{c.label}</div>
                  </div>
                ))}
              </div>
            </Body>
          </Panel>
          {data && (
            <>
              <Split title="Query Response Types" data={data.queryResponseChartData} />
              <Split title="Query Types" data={data.queryTypeChartData} />
              <Split title="Protocol Types" data={data.protocolTypeChartData} />
            </>
          )}
          <Top
            title="Top Clients"
            rows={data?.topClients ?? []}
            isClient
            onMore={() => setTop('TopClients')}
          />
        </div>
      </div>

      <TopStats type={top} range={range} token={token} onClose={() => setTop(null)} />
    </>
  )
}
