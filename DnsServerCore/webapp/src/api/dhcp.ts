import { apiRequest, type ApiOutcome } from './client'

/*
The `dhcp` family: ten endpoints, all of them in upstream's `dhcp.js`.

Five things about the server that are NOT deducible from looking at the
JavaScript and that govern the two screens:

  1. **Null fields are OMITTED, they do not arrive as `null`.**
     `WebServiceDhcpApi.cs:127-364` writes each optional property inside an
     `if (… is not null)`. In `scopes/list`, `interfaceAddress` is missing as
     soon as the scope is not bound to an interface; in `scopes/get` the missing
     ones are `domainName`, `domainSearchList`, `serverAddress`,
     `serverHostName`, `bootFileName`, `routerAddress`, `dnsServers`,
     `winsServers`, `ntpServers`, `ntpServerDomainNames`, `staticRoutes`,
     `vendorInfo`, `capwapAcIpAddresses`, `tftpServerAddresses`,
     `genericOptions` and `exclusions`. Verified against a freshly installed
     v15.4 instance, which returns a scope without half of those keys. Typing
     them as required fails. `reservedLeases` is the exception: it is ALWAYS
     written, even if it is `[]`.

  2. **`scopes/set` sends the body by POST but the `node` in the QUERY**
     (dhcp.js:558-567). That is honoured to the letter.

  3. **Renaming is the same endpoint**: if the name changed, the OLD name is sent
     in `name` and the new one in `newName` (dhcp.js:486-493). No `newName` on a
     new scope.

  4. **`dnsServers` is not sent when `useThisDnsServer` is checked**
     (dhcp.js:565). It is not a cosmetic detail: the server keeps the ones it had
     stored, and in fact `scopes/get` still returns them.

  5. **The permissions are asymmetric.** `WebServiceDhcpApi.cs`: the three `list`
     and `get` ask for `DhcpServer.View`; `scopes/set`, `enable`, `disable` and
     the two lease conversions ask for `Modify`; but `scopes/delete` and
     `leases/remove` ask for `Delete`. Deleting a scope is NOT `Modify`.
*/

/** A lease from `dhcp/leases/list`. Every field is always written
 *  (`WebServiceDhcpApi.cs:90-101`), but `hostName` can come `null`. */
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

/** A row of `dhcp/scopes/list`. `interfaceAddress` is missing if it is null. */
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

/** `dhcp/scopes/get`. Only the keys the server writes unconditionally are
 *  required; the rest are optional because they are OMITTED (see the header). */
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
  /** Always written, even if it comes empty. */
  reservedLeases: ReservedLease[]
  allowOnlyReservedLeases: boolean
  blockLocallyAdministeredMacAddresses: boolean
  ignoreClientIdentifierOption: boolean
}

/*
Returns the whole outcome, not a list.

It used to return `[]` when the server failed, and that looked prudent —"the
screen does not blow up if the request falls over". It was the opposite: an empty
list and a failure draw the same, so the screen said "No Lease Found" when what
had happened was that the call never arrived. That is worse than an error,
because nobody suspects a response that looks normal.

By returning the `ApiOutcome` —as the list screens already did, and those did
warn— the type forces the two apart, and the message the server sent is kept as
well, which is what upstream shows.
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
The three actions on a lease are identified by the pair `name` (the scope) +
`clientIdentifier`. The server also accepts `hardwareAddress` as an alternative
(`WebServiceDhcpApi.cs:775-790`), but upstream ALWAYS sends the clientIdentifier,
so here too.
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

/** `dhcp/scopes/list` (dhcp.js:220). See `listLeases` for why it returns the
 *  whole outcome and not a list. */
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

/** `dhcp/scopes/get` (dhcp.js:377). `null` if the server fails. */
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
`dhcp/scopes/set` (dhcp.js:558). POST with the encoded body and the `node` in
the query, exactly like upstream. The body is built by `construirCuerpo` in
`screens/dhcp/model.ts`, which is the one that knows the form.
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
