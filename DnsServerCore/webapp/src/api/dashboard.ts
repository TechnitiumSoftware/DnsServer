import { apiRequest, type ApiOutcome } from './client'

/*
Los tres endpoints de la familia `dashboard`.

La respuesta de `stats/get` viene envuelta en `response` y trae CUATRO conjuntos
de gráfica, no dos: la principal de líneas y tres de reparto —tipo de respuesta,
tipo de consulta y protocolo—. Verificado contra v15.4.
*/

export const RANGOS = ['LastHour', 'LastDay', 'LastWeek', 'LastMonth', 'LastYear', 'Custom'] as const
export type Rango = (typeof RANGOS)[number]

/** Etiquetas literales de upstream para cada rango. */
export const ETIQUETA_RANGO: Record<Rango, string> = {
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

/** Formato de Chart.js, que es el que emite el servidor. */
export interface ChartData {
  labelFormat?: string
  labels: string[]
  datasets: { label: string; data: number[]; backgroundColor?: string | string[] }[]
}

/*
Un top NO es sólo nombre y aciertos. Un cliente trae además el dominio que
resolvió y si el servidor lo estaba limitando, y upstream pinta las dos cosas:
el dominio debajo del nombre, y la fila en naranja con «(rate limited)» detrás.
Los dos campos sólo existen en `TopClients`. Comprobado contra v15.4.
*/
export interface TopEntry {
  name: string
  hits: number
  /** Sólo en clientes: el dominio que resolvió. Vacío se pinta como «.». */
  domain?: string
  /** Sólo en clientes. */
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
  type: Rango = 'LastHour',
  rango?: { start: string; end: string },
): Promise<DashboardStats | null> {
  const body: Record<string, string> = { type }
  if (type === 'Custom' && rango) {
    body.start = rango.start
    body.end = rango.end
  }
  const outcome = await apiRequest<{ response: DashboardStats }>('dashboard/stats/get', { token, body })
  return outcome.kind === 'ok' ? outcome.data.response : null
}

export type TipoTop = 'TopClients' | 'TopDomains' | 'TopBlockedDomains'

export async function getTop(
  token: string | null,
  statsType: Rango,
  type: TipoTop,
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
