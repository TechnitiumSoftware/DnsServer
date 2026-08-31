import { apiRequest, type ApiOutcome } from './client'

/*
La familia `dhcp`: diez endpoints, todos en `dhcp.js` de upstream.

Cinco cosas del servidor que NO se deducen mirando el JavaScript y que gobiernan
las dos pantallas:

  1. **Los campos nulos se OMITEN, no llegan como `null`.**
     `WebServiceDhcpApi.cs:127-364` escribe cada propiedad opcional dentro de un
     `if (… is not null)`. En `scopes/list` falta `interfaceAddress` en cuanto el
     scope no está enlazado a una interfaz; en `scopes/get` faltan `domainName`,
     `domainSearchList`, `serverAddress`, `serverHostName`, `bootFileName`,
     `routerAddress`, `dnsServers`, `winsServers`, `ntpServers`,
     `ntpServerDomainNames`, `staticRoutes`, `vendorInfo`,
     `capwapAcIpAddresses`, `tftpServerAddresses`, `genericOptions` y
     `exclusions`. Verificado contra una instancia v15.4 recién instalada, que
     devuelve un scope sin la mitad de esas claves. Tiparlas obligatorias falla.
     `reservedLeases` es la excepción: se escribe SIEMPRE, aunque sea `[]`.

  2. **`scopes/set` manda el cuerpo por POST pero el `node` en la QUERY**
     (dhcp.js:558-567). Se respeta al pie de la letra.

  3. **Renombrar es el mismo endpoint**: si el nombre cambió, se manda el nombre
     VIEJO en `name` y el nuevo en `newName` (dhcp.js:486-493). Sin `newName` en
     un scope nuevo.

  4. **`dnsServers` no se manda cuando `useThisDnsServer` está marcado**
     (dhcp.js:565). No es un detalle cosmético: el servidor conserva los que
     tenía guardados, y de hecho `scopes/get` sigue devolviéndolos.

  5. **Los permisos son asimétricos.** `WebServiceDhcpApi.cs`: los tres `list`
     y `get` piden `DhcpServer.View`; `scopes/set`, `enable`, `disable` y las
     dos conversiones de lease piden `Modify`; pero `scopes/delete` y
     `leases/remove` piden `Delete`. Borrar un scope NO es `Modify`.
*/

/** Una concesión de `dhcp/leases/list`. Todos los campos se escriben siempre
 *  (`WebServiceDhcpApi.cs:90-101`), pero `hostName` puede venir `null`. */
export interface DhcpLease {
  scope: string
  /** `Dynamic` o `Reserved`. */
  type: string
  /** Formato `AA-BB-CC-DD-EE-FF` (BitConverter.ToString). */
  hardwareAddress: string
  clientIdentifier: string
  address: string
  hostName: string | null
  leaseObtained: string
  leaseExpires: string
}

/** Una fila de `dhcp/scopes/list`. `interfaceAddress` falta si es nula. */
export interface DhcpScopeRow {
  name: string
  enabled: boolean
  startingAddress: string
  endingAddress: string
  subnetMask: string
  networkAddress: string
  broadcastAddress: string
  interfaceAddress?: string
}

export interface StaticRoute {
  destination: string
  subnetMask: string
  router: string
}

export interface VendorInfo {
  identifier: string
  information: string
}

export interface GenericOption {
  code: number
  value: string
}

export interface Exclusion {
  startingAddress: string
  endingAddress: string
}

export interface ReservedLease {
  hostName: string | null
  hardwareAddress: string
  address: string
  comments: string | null
}

/** `dhcp/scopes/get`. Sólo son obligatorias las claves que el servidor escribe
 *  incondicionalmente; el resto son opcionales porque SE OMITEN (ver cabecera). */
export interface DhcpScope {
  name: string
  startingAddress: string
  endingAddress: string
  subnetMask: string
  leaseTimeDays: number
  leaseTimeHours: number
  leaseTimeMinutes: number
  offerDelayTime: number
  pingCheckEnabled: boolean
  pingCheckTimeout: number
  pingCheckRetries: number
  domainName?: string
  domainSearchList?: string[]
  dnsUpdates: boolean
  dnsOverwriteForDynamicLease: boolean
  dnsTtl: number
  serverAddress?: string
  serverHostName?: string
  bootFileName?: string
  routerAddress?: string
  useThisDnsServer: boolean
  dnsServers?: string[]
  winsServers?: string[]
  ntpServers?: string[]
  ntpServerDomainNames?: string[]
  staticRoutes?: StaticRoute[]
  vendorInfo?: VendorInfo[]
  capwapAcIpAddresses?: string[]
  tftpServerAddresses?: string[]
  genericOptions?: GenericOption[]
  exclusions?: Exclusion[]
  /** Se escribe siempre, aunque venga vacío. */
  reservedLeases: ReservedLease[]
  allowOnlyReservedLeases: boolean
  blockLocallyAdministeredMacAddresses: boolean
  ignoreClientIdentifierOption: boolean
}

/*
Devuelve el resultado entero, no una lista.

Antes devolvía `[]` cuando el servidor fallaba, y eso parecía prudente —«la
pantalla no revienta si la petición se cae»—. Era lo contrario: la lista vacía y
el fallo se pintan igual, así que la pantalla decía «No Lease Found» cuando lo que había
pasado es que la llamada no llegó. Eso es peor que un error, porque nadie
sospecha de una respuesta que parece normal.

Devolviendo el `ApiOutcome` —como ya hacían las pantallas de listas, que sí
avisaban— el tipo obliga a distinguirlos y además se conserva el mensaje que
mandó el servidor, que es lo que enseña upstream.
*/
/** `dhcp/leases/list` (dhcp.js:46). */
export async function listLeases(
  token: string | null,
  node = '',
): Promise<ApiOutcome<DhcpLease[]>> {
  const outcome = await apiRequest<{ response: { leases: DhcpLease[] } }>('dhcp/leases/list', {
    token,
    body: { node },
  })
  return outcome.kind === 'ok'
    ? { kind: 'ok', data: outcome.data.response.leases ?? [] }
    : outcome
}

/*
Las tres acciones sobre una concesión se identifican con el par
`name` (el scope) + `clientIdentifier`. El servidor acepta también
`hardwareAddress` como alternativa (`WebServiceDhcpApi.cs:775-790`), pero
upstream manda SIEMPRE el clientIdentifier, así que aquí también.
*/
export function removeLease(
  token: string | null,
  name: string,
  clientIdentifier: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('dhcp/leases/remove', { token, body: { name, clientIdentifier, node } })
}

export function convertToReservedLease(
  token: string | null,
  name: string,
  clientIdentifier: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('dhcp/leases/convertToReserved', {
    token,
    body: { name, clientIdentifier, node },
  })
}

export function convertToDynamicLease(
  token: string | null,
  name: string,
  clientIdentifier: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('dhcp/leases/convertToDynamic', {
    token,
    body: { name, clientIdentifier, node },
  })
}

/** `dhcp/scopes/list` (dhcp.js:220). Ver `listLeases` para por qué devuelve
 *  el resultado entero y no una lista. */
export async function listScopes(
  token: string | null,
  node = '',
): Promise<ApiOutcome<DhcpScopeRow[]>> {
  const outcome = await apiRequest<{ response: { scopes: DhcpScopeRow[] } }>('dhcp/scopes/list', {
    token,
    body: { node },
  })
  return outcome.kind === 'ok'
    ? { kind: 'ok', data: outcome.data.response.scopes ?? [] }
    : outcome
}

/** `dhcp/scopes/get` (dhcp.js:377). `null` si el servidor falla. */
export async function getScope(
  token: string | null,
  name: string,
  node = '',
): Promise<DhcpScope | null> {
  const outcome = await apiRequest<{ response: DhcpScope }>('dhcp/scopes/get', {
    token,
    body: { name, node },
  })
  return outcome.kind === 'ok' ? outcome.data.response : null
}

/*
`dhcp/scopes/set` (dhcp.js:558). POST con el cuerpo codificado y el `node` en la
query, exactamente como upstream. El cuerpo lo arma `construirCuerpo` de
`screens/dhcp/model.ts`, que es quien conoce el formulario.
*/
export function setScope(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest(`dhcp/scopes/set?node=${encodeURIComponent(node)}`, {
    token,
    method: 'POST',
    body,
  })
}

export function enableScope(token: string | null, name: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('dhcp/scopes/enable', { token, body: { name, node } })
}

export function disableScope(token: string | null, name: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('dhcp/scopes/disable', { token, body: { name, node } })
}

export function deleteScope(token: string | null, name: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('dhcp/scopes/delete', { token, body: { name, node } })
}
