import { apiRequest, type ApiOutcome } from './client'

/*
The twelve cluster endpoints (`cluster.js`). It is Administration's sixth
sub-tab and goes in a file of its own because in upstream it does too.

Five things to keep in front of you:

  1. **Half the response disappears when there is no cluster.**
     `WriteClusterState` (WebServiceClusterApi.cs:60-75) writes `clusterDomain`,
     the four intervals and `clusterNodes` ONLY if `clusterInitialized`. On a
     standalone server the response is three fields. Typing them as required is a
     guaranteed bug; verified live against an instance with no cluster.

  2. **A node's dates are OMITTED when they hold `default`**, they do not arrive
     as `null`: `upSince`, `lastSeen` and `configLastSynced` (same file, lines
     137-152). And `configLastSynced` only exists for the node itself when it is
     also a secondary.

  3. **The permissions are asymmetric and do not follow the verb.** Nearly
     everything asks for `Administration.canDelete` —including `init`, `initJoin`
     and `promote`—, but `setOptions`, `resync`, `updatePrimary` and
     `updateIpAddress` ask for `canModify`, and `state` asks for `canView`.
     Looked at one by one in WebServiceClusterApi.cs.

  4. **`secondary/resync` returns no state.** It is the only one that does not
     call `WriteClusterState`: it answers a bare `ok` and the result is checked
     in the Logs.

  5. **`initJoin` can answer `2fa-required`.** It is the only one of the family
     that does, because it authenticates against the primary node with a username
     and password. `apiRequest` already translates it to `two-factor-required`.

`node` is the cluster node the request is aimed at (DnsWebService.cs:2367); empty
means "this server". They all send it except `init` and `initJoin`, which by
definition run on the server being looked at.
*/

export type ClusterNodeType = 'Primary' | 'Secondary' | (string & {})
export type ClusterNodeState = 'Self' | 'Connected' | 'Unreachable' | (string & {})

export interface ClusterNode {
  id: number
  name: string
  url: string
  ipAddresses: string[]
  type: ClusterNodeType
  state: ClusterNodeState
  /** Omitido si nunca ha estado arriba. */
  upSince?: string
  /** Omitted for the node itself and if it has never been seen. */
  lastSeen?: string
  /** Only for the node itself when it is a secondary, and only once it has synced. */
  configLastSynced?: string
}

export interface ClusterState {
  version: string
  dnsServerDomain: string
  clusterInitialized: boolean
  /* The next five ONLY exist with the cluster initialised. */
  clusterDomain?: string
  heartbeatRefreshIntervalSeconds?: number
  heartbeatRetryIntervalSeconds?: number
  configRefreshIntervalSeconds?: number
  configRetryIntervalSeconds?: number
  clusterNodes?: ClusterNode[]
  /** Only with `includeServerIpAddresses=true`. */
  serverIpAddresses?: string[]
}

type Env<T> = { response: T; server: string }
export type ClusterOutcome = ApiOutcome<Env<ClusterState>>

export function getClusterState(
  token: string | null,
  opts: { node?: string; includeServerIpAddresses?: boolean } = {},
): Promise<ClusterOutcome> {
  const body: Record<string, string> = {}
  if (opts.includeServerIpAddresses) body.includeServerIpAddresses = 'true'
  if (opts.node !== undefined) body.node = opts.node
  return apiRequest('admin/cluster/state', { token, body })
}

/** `initializeNewCluster` (cluster.js:592). No `node`: it initialises here. */
export function initCluster(
  token: string | null,
  clusterDomain: string,
  primaryNodeIpAddresses: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/init', {
    token,
    body: { clusterDomain, primaryNodeIpAddresses },
  })
}

/** `initializeJoinCluster` (cluster.js:692). POST: it carries the primary node
 *  administrator's password. It can answer `2fa-required`. */
export function initJoinCluster(
  token: string | null,
  body: {
    secondaryNodeIpAddresses: string
    primaryNodeUrl: string
    primaryNodeIpAddress: string
    ignoreCertificateErrors: string
    primaryNodeUsername: string
    primaryNodePassword: string
    primaryNodeTotp: string
  },
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/initJoin', { token, method: 'POST', body })
}

/** `updateSelfClusterNode` (cluster.js:326). */
export function updateIpAddress(
  token: string | null,
  ipAddresses: string,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/updateIpAddress', { token, body: { ipAddresses, node } })
}

/** `saveClusterOptions` (cluster.js:874). Only the primary can save it. */
export function setClusterOptions(
  token: string | null,
  opciones: {
    heartbeatRefreshIntervalSeconds: string
    heartbeatRetryIntervalSeconds: string
    configRefreshIntervalSeconds: string
    configRetryIntervalSeconds: string
  },
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/primary/setOptions', { token, body: { ...opciones, node } })
}

/** `deleteCluster` (cluster.js:975). */
export function deleteCluster(
  token: string | null,
  forceDelete: boolean,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/primary/delete', {
    token,
    body: { forceDelete: String(forceDelete), node },
  })
}

/*
`removeSecondaryClusterNode` (cluster.js:437) picks the endpoint by the "Force
Remove Node" checkbox: checked, it deletes the secondary without telling it;
unchecked, it asks it to leave. They are two different endpoints with the same
body.
*/
export function deleteSecondaryNode(
  token: string | null,
  secondaryNodeId: string,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/primary/deleteSecondary', {
    token,
    body: { secondaryNodeId, node },
  })
}

export function removeSecondaryNode(
  token: string | null,
  secondaryNodeId: string,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/primary/removeSecondary', {
    token,
    body: { secondaryNodeId, node },
  })
}

/** `leaveCluster` (cluster.js:930). */
export function leaveCluster(
  token: string | null,
  forceLeave: boolean,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/secondary/leave', {
    token,
    body: { forceLeave: String(forceLeave), node },
  })
}

/** `promoteToPrimaryClusterNode` (cluster.js:512). */
export function promoteToPrimary(
  token: string | null,
  forceDeletePrimary: boolean,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/secondary/promote', {
    token,
    body: { forceDeletePrimary: String(forceDeletePrimary), node },
  })
}

/** `resyncCluster` (cluster.js:761). The ONLY one that does not return the state. */
export function resyncCluster(token: string | null, node: string): Promise<ApiOutcome> {
  return apiRequest('admin/cluster/secondary/resync', { token, body: { node } })
}

/** `updatePrimaryClusterNode` (cluster.js:390). */
export function updatePrimaryNode(
  token: string | null,
  primaryNodeUrl: string,
  primaryNodeIpAddresses: string,
  node: string,
): Promise<ClusterOutcome> {
  return apiRequest('admin/cluster/secondary/updatePrimary', {
    token,
    body: { primaryNodeUrl, primaryNodeIpAddresses, node },
  })
}

/** `getPrimaryClusterNodeName` (cluster.js:1013): the primary node's name, or an
 *  empty string if the cluster is not initialised. It governs the `node` of
 *  `permissions/set` and the one of `sessions/delete` for API tokens. */
export function primaryNodeName(state: ClusterState | null): string {
  if (!state?.clusterInitialized) return ''
  return state.clusterNodes?.find((n) => n.type === 'Primary')?.name ?? ''
}
