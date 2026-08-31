import { Leases } from './Leases'
import { Scopes } from './Scopes'

/*
DHCP. Two sub-tabs, with upstream's literal labels (index.html:2496-2497):
"Leases" and "Scopes".

The sub-navigation is NOT mounted here: it lives in the Shell's side panel, just
like Settings', and arrives through the `sub` prop. Unlike Settings, the two
sub-tabs are independent screens —each with its own loading and its own state— so
they can be split up: in upstream they are two different functions,
`refreshDhcpLeases` and `refreshDhcpScopes`, and they share no form.

Upstream's cluster node selector (`optDhcpClusterNode`) is not mounted: this
console has no cluster mode yet. The `node` parameter travels all the same,
empty, on all ten calls, which is what upstream sends with a single server.
*/

export const SUBPESTANAS = ['Leases', 'Scopes'] as const
export type Subpestana = (typeof SUBPESTANAS)[number]

export interface DhcpProps {
  token: string | null
  /** The active sub-tab, the one the Shell's side panel marks. */
  sub?: string | null
  /** It exists for symmetry with Settings; this screen never forces a change. */
  onSubChange?: (sub: Subpestana) => void
  /** `DhcpServer.canModify`: saving a scope, enabling it, disabling it and
   *  converting a lease (`WebServiceDhcpApi.cs:379,708,733,805,835`). */
  canModify?: boolean
  /** `DhcpServer.canDelete`: deleting a scope and removing a lease
   *  (`WebServiceDhcpApi.cs:761,775`). Careful: it is NOT `canModify`. */
  canDelete?: boolean
  /** The cluster node. Empty means "this server". */
  node?: string
}

export function Dhcp({
  token,
  sub,
  canModify = true,
  canDelete = true,
  node = '',
}: DhcpProps) {
  const pedida = (sub ?? 'Leases') as Subpestana
  const activa: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'Leases'

  return activa === 'Scopes' ? (
    <Scopes token={token} node={node} canModify={canModify} canDelete={canDelete} />
  ) : (
    <Leases token={token} node={node} canModify={canModify} canDelete={canDelete} />
  )
}
