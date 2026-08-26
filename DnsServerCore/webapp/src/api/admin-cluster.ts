import { apiRequest, type ApiOutcome } from './client'

/*
Los doce endpoints del cluster (`cluster.js`). Es la sexta sub-pestaña de
Administration y va en fichero aparte porque en upstream también lo va.

Cinco cosas que hay que tener delante:

  1. **Media respuesta desaparece cuando no hay cluster.** `WriteClusterState`
     (WebServiceClusterApi.cs:60-75) escribe `clusterDomain`, los cuatro
     intervalos y `clusterNodes` SÓLO si `clusterInitialized`. En un servidor
     suelto la respuesta son tres campos. Tiparlos obligatorios es un error
     garantizado; verificado en vivo contra una instancia sin cluster.

  2. **Las fechas de un nodo se OMITEN cuando valen `default`**, no llegan como
     `null`: `upSince`, `lastSeen` y `configLastSynced` (mismo fichero,
     líneas 137-152). Y `configLastSynced` sólo existe para el nodo propio
     cuando además es secundario.

  3. **Los permisos son asimétricos y no siguen al verbo.** Casi todo pide
     `Administration.canDelete` —incluido `init`, `initJoin` y `promote`—, pero
     `setOptions`, `resync`, `updatePrimary` y `updateIpAddress` piden
     `canModify`, y `state` pide `canView`. Mirados uno a uno en
     WebServiceClusterApi.cs.

  4. **`secondary/resync` no devuelve estado.** Es el único que no llama a
     `WriteClusterState`: responde `ok` a secas y el resultado se comprueba en
     los Logs.

  5. **`initJoin` puede responder `2fa-required`.** Es el único de la familia
     que lo hace, porque autentica contra el nodo primario con usuario y
     contraseña. `apiRequest` ya lo traduce a `two-factor-required`.

`node` es el nodo del cluster al que se dirige la petición
(DnsWebService.cs:2367); vacío significa «este servidor». Lo mandan todos menos
`init` e `initJoin`, que por definición se ejecutan en el servidor que se está
mirando.
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
  /** Omitido para el nodo propio y si nunca se ha visto. */
  lastSeen?: string
  /** Sólo para el nodo propio cuando es secundario, y sólo si ya sincronizó. */
  configLastSynced?: string
}

export interface ClusterState {
  version: string
  dnsServerDomain: string
  clusterInitialized: boolean
  /* Los cinco siguientes SÓLO existen con el cluster inicializado. */
  clusterDomain?: string
  heartbeatRefreshIntervalSeconds?: number
  heartbeatRetryIntervalSeconds?: number
  configRefreshIntervalSeconds?: number
  configRetryIntervalSeconds?: number
  clusterNodes?: ClusterNode[]
  /** Sólo con `includeServerIpAddresses=true`. */
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

/** `initializeNewCluster` (cluster.js:592). Sin `node`: se inicializa aquí. */
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

/** `initializeJoinCluster` (cluster.js:692). POST: lleva la contraseña del
 *  administrador del nodo primario. Puede responder `2fa-required`. */
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

/** `saveClusterOptions` (cluster.js:874). Sólo lo puede guardar el primario. */
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
`removeSecondaryClusterNode` (cluster.js:437) elige el endpoint según la casilla
«Force Remove Node»: marcada, borra el secundario sin avisarle; sin marcar, le
pide que se vaya. Son dos endpoints distintos con el mismo cuerpo.
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

/** `resyncCluster` (cluster.js:761). El ÚNICO que no devuelve el estado. */
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

/** `getPrimaryClusterNodeName` (cluster.js:1013): el nombre del nodo primario,
 *  o cadena vacía si el cluster no está inicializado. Gobierna el `node` de
 *  `permissions/set` y el de `sessions/delete` para los tokens de API. */
export function primaryNodeName(state: ClusterState | null): string {
  if (!state?.clusterInitialized) return ''
  return state.clusterNodes?.find((n) => n.type === 'Primary')?.name ?? ''
}
