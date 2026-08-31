import { QueryLogs } from './QueryLogs'
import { ViewLogs } from './ViewLogs'

/*
Logs. Two sub-tabs, with upstream's literal labels (index.html:3243-3244): "View
Logs" and "Query Logs".

As in DHCP, the sub-navigation lives in the Shell's side panel and arrives
through the `sub` prop. The two sub-tabs are independent screens: in upstream
they are `refreshLogFilesList` and `refreshQueryLogsTab`, with no shared state.

The section's permissions are NOT a single one. The whole tab shows with
`Logs.canView`, but inside there are three delete actions and one of them belongs
to another section: "delete all stats" deletes the Dashboard's statistics and
asks for `Dashboard.canDelete` (`WebServiceLogsApi.cs:135`).
*/

export const SUB_TABS = ['View Logs', 'Query Logs'] as const
export type SubTab = (typeof SUB_TABS)[number]

export interface LogsProps {
  token: string | null
  /** The active sub-tab, the one the Shell's side panel marks. */
  sub?: string | null
  /** It exists for symmetry with Settings; this screen never forces a change. */
  onSubChange?: (sub: SubTab) => void
  /** `Logs.canDelete`: deleting a log file and deleting them all. */
  canDeleteLogs?: boolean
  /** `Dashboard.canDelete`: deleting all the statistics. */
  canDeleteStats?: boolean
  /** The cluster node. Empty means "this server". */
  node?: string
}

export function Logs({
  token,
  sub,
  canDeleteLogs = true,
  canDeleteStats = true,
  node = '',
}: LogsProps) {
  const requested = (sub ?? 'View Logs') as SubTab
  const active: SubTab = SUB_TABS.includes(requested) ? requested : 'View Logs'

  return active === 'Query Logs' ? (
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
