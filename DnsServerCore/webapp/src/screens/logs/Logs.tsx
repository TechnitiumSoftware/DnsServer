import { QueryLogs } from './QueryLogs'
import { ViewLogs } from './ViewLogs'

/*
Logs. Dos sub-pestañas, con las etiquetas literales de upstream
(index.html:3243-3244): «View Logs» y «Query Logs».

Como en DHCP, la sub-navegación vive en el panel lateral del Shell y llega por
la prop `sub`. Las dos sub-pestañas son pantallas independientes: en upstream
son `refreshLogFilesList` y `refreshQueryLogsTab`, sin estado compartido.

Los permisos de la sección NO son uno solo. La pestaña entera se ve con
`Logs.canView`, pero dentro hay tres acciones de borrado y una de ellas es de
otra sección: «delete all stats» borra las estadísticas del Dashboard y pide
`Dashboard.canDelete` (`WebServiceLogsApi.cs:135`).
*/

export const SUBPESTANAS = ['View Logs', 'Query Logs'] as const
export type Subpestana = (typeof SUBPESTANAS)[number]

export interface LogsProps {
  token: string | null
  /** Sub-pestaña activa, la que marca el panel lateral del Shell. */
  sub?: string | null
  /** Existe por simetría con Settings; esta pantalla nunca fuerza un cambio. */
  onSubChange?: (sub: Subpestana) => void
  /** `Logs.canDelete`: borrar un fichero de log y borrarlos todos. */
  canDeleteLogs?: boolean
  /** `Dashboard.canDelete`: borrar todas las estadísticas. */
  canDeleteStats?: boolean
  /** Nodo del clúster. Vacío significa «este servidor». */
  node?: string
}

export function Logs({
  token,
  sub,
  canDeleteLogs = true,
  canDeleteStats = true,
  node = '',
}: LogsProps) {
  const pedida = (sub ?? 'View Logs') as Subpestana
  const activa: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'View Logs'

  return activa === 'Query Logs' ? (
    <QueryLogs token={token} node={node} />
  ) : (
    <ViewLogs
      token={token}
      node={node}
      canDeleteLogs={canDeleteLogs}
      canDeleteStats={canDeleteStats}
    />
  )
}
