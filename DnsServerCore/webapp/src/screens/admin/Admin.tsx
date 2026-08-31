import { useCallback, useEffect, useState } from 'react'
import { getClusterState, type ClusterState } from '../../api/admin-cluster'
import { Sessions } from './Sessions'
import { Users } from './Users'
import { Groups } from './Groups'
import { Permissions } from './Permissions'
import { Sso } from './Sso'
import { Cluster } from './Cluster'
import { Avisador, type Aviso } from './partes'

/*
Administration. Six sub-tabs and thirty endpoints: the console's second largest
block after Zones.

The sub-navigation is NOT mounted here. Just as in Settings, the sub-tabs live in
the Shell's side panel and arrive through the `sub` prop. This component only
decides which panel it draws and holds the two things all six share: the page
alert and the cluster's state.

About the permissions, and it goes against intuition: **upstream hides and
disables NOTHING inside Administration**. The only check it makes is
`permissions.Administration.canView` to show or hide the whole section
(main.js:165 and 240), and from there it shows every button and lets the server
reject whatever it should. That is why this component receives no permission
props: adding them would be adding behaviour. The permissions each action
consumes are noted in `src/api/admin.ts` and `src/api/admin-cluster.ts`.

About the cluster: upstream reads `clusterInitialized` and `clusterNodes` from
`sessionData.info`, which arrives on login. The session the Shell hands out does
not expose them, so here they are asked for once with `admin/cluster/state` —the
same datum, and allowed with the same `canView` needed to see the section— and
shared with the six sub-tabs. The Cluster sub-tab refreshes it every time it
changes, just as `reloadAdminClusterView` does.
*/

export const SUBPESTANAS = ['Sessions', 'Users', 'Groups', 'Permissions', 'SSO', 'Cluster'] as const

export type Subpestana = (typeof SUBPESTANAS)[number]

export interface AdminProps {
  token: string | null
  /** The active sub-tab, the one the Shell's side panel marks. */
  sub?: string | null
  /** Present for symmetry with Settings; Administration never changes sub-tab on
   *  its own, so today it is not invoked. */
  onSubChange?: (sub: Subpestana) => void
}

export function Admin({ token, sub }: AdminProps) {
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cluster, setCluster] = useState<ClusterState | null>(null)

  useEffect(() => {
    let vivo = true
    void getClusterState(token).then((outcome) => {
      if (vivo && outcome.kind === 'ok') setCluster(outcome.data.response)
    })
    return () => {
      vivo = false
    }
  }, [token])

  // Stable across renders: the sub-tabs put it in the dependencies of their
  // loading `useCallback`, and a new function per render would reload them in
  // bucle.
  const avisar = useCallback((a: Aviso) => setAviso(a), [])
  const alCluster = useCallback((s: ClusterState) => setCluster(s), [])

  const pedida = (sub ?? 'Sessions') as Subpestana
  const activa: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'Sessions'

  return (
    <div>
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {activa === 'Sessions' && <Sessions token={token} cluster={cluster} onAviso={avisar} />}
      {activa === 'Users' && <Users token={token} cluster={cluster} onAviso={avisar} />}
      {activa === 'Groups' && <Groups token={token} onAviso={avisar} />}
      {activa === 'Permissions' && (
        <Permissions token={token} cluster={cluster} onAviso={avisar} />
      )}
      {activa === 'SSO' && <Sso token={token} onAviso={avisar} />}
      {activa === 'Cluster' && (
        <Cluster token={token} cluster={cluster} onCluster={alCluster} onAviso={avisar} />
      )}
    </div>
  )
}
