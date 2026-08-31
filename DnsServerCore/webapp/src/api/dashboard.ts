import { apiRequest, type ApiOutcome } from './client'

/*
The three endpoints of the `dashboard` family.

The response of `stats/get` comes wrapped in `response` and brings FOUR chart
sets, not two: the main line one and three breakdowns —response type, query type
and protocol. Verified against v15.4.
*/

export const RANGES = ['LastHour', 'LastDay', 'LastWeek', 'LastMonth', 'LastYear', 'Custom'] as const
export type Range = (typeof RANGES)[number]

/** Upstream's literal labels for each range. */
export const RANGE_LABEL: Record<Range, string> = {
  LastHour: 'Last Hour',
  LastDay: 'Last Day',
  LastWeek: 'Last Week',
  LastMonth: 'Last Month',
  LastYear: 'Last Year',
  Custom: 'Custom',
}

export interface Stats {
  totalQueries: number
  totalNoError: number
  totalServerFailure: number
  totalNxDomain: number
  totalRefused: number
  totalAuthoritative: number
  totalRecursive: number
  totalCached: number
  totalBlocked: number
  totalDropped: number
  totalClients: number
  zones: number
  cachedEntries: number
  allowedZones: number
  blockedZones: number
  allowListZones: number
  blockListZones: number
}

/** Chart.js's format, which is the one the server emits. */
export interface ChartData {
  labelFormat?: string
  labels: string[]
  datasets: { label: string; data: number[]; backgroundColor?: string | string[] }[]
}

/*
A top is NOT just a name and a hit count. A client also brings the domain it
resolved and whether the server was rate-limiting it, and upstream draws both:
the domain under the name, and the row in orange with "(rate limited)" after it.
The two fields only exist in `TopClients`. Checked against v15.4.
*/
export interface TopEntry {
  name: string
  hits: number
  /** Only on clients: the domain it resolved. Empty is drawn as ".". */
  domain?: string
  /** Only on clients. */
  rateLimited?: boolean
}

export interface DashboardStats {
  stats: Stats
  mainChartData: ChartData
  queryResponseChartData: ChartData
  queryTypeChartData: ChartData
  protocolTypeChartData: ChartData
  topClients: TopEntry[]
  topDomains: TopEntry[]
  topBlockedDomains: TopEntry[]
}

export async function getDashboardStats(
  token: string | null,
  type: Range = 'LastHour',
  range?: { start: string; end: string },
): Promise<ApiOutcome<DashboardStats>> {
  const body: Record<string, string> = { type }
  if (type === 'Custom' && range) {
    body.start = range.start
    body.end = range.end
  }
  const outcome = await apiRequest<{ response: DashboardStats }>('dashboard/stats/get', { token, body })
  /*
  Returns the whole outcome and not `DashboardStats | null`.

  With `null` the Dashboard could not tell "the server has served no queries"
  apart from "the call fell over", and both were drawn the same: eleven tiles at
  zero and "No queries for this period.". It is the console's worst lie —whoever
  administers a DNS and reads that concludes their server is receiving no
  traffic— and the easiest to believe, because it looks exactly like a normal
  response.
  */
  return outcome.kind === 'ok' ? { kind: 'ok', data: outcome.data.response } : outcome
}

export type TopKind = 'TopClients' | 'TopDomains' | 'TopBlockedDomains'

export async function getTop(
  token: string | null,
  statsType: Range,
  type: TopKind,
  limit = 1000,
): Promise<TopEntry[]> {
  const outcome = await apiRequest<{ response: Record<string, TopEntry[]> }>('dashboard/stats/getTop', {
    token,
    body: { type: statsType, statsType: type, limit: String(limit) },
  })
  if (outcome.kind !== 'ok') return []
  const r = outcome.data.response
  return r.topClients ?? r.topDomains ?? r.topBlockedDomains ?? []
}

export function deleteAllStats(token: string | null): Promise<ApiOutcome> {
  return apiRequest('dashboard/stats/deleteAll', { token })
}
