import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'

/*
The three domain lists that are NOT authoritative zones: `cache`, `allowed` and
`blocked`. Fifteen endpoints, all of them in `other-zones.js`.

All three are navigated the same way —a tree of domains, one node at a time— and
their three `list` endpoints return the same envelope: `domain`, `domainIdn`,
`zones` and `records`. That is why they share a module and share a screen.

Four things about the server that are not deducible from looking at upstream's
JavaScript and that govern the screen:

  1. **The server can RETURN A DOMAIN DIFFERENT FROM THE ONE ASKED FOR.**
     `WebServiceOtherZonesApi.cs:88-120` walks down the chain on its own while
     the node has no records and has exactly one child: asking for `org` with a
     single `example.org` underneath returns `example.org` and ITS records. With
     `direction=up` the same condition walks up. That is why whoever draws the
     tree must ALWAYS use `response.domain`, never the domain it asked for.

  2. **`zones` brings FULL domain names**, not labels: the server concatenates
     `subZone + "." + domain` (same source, lines 133-146) and converts them to
     Unicode if they are IDN. They are navigated as they come, recomposing
     nothing.

  3. **`records` does NOT have the same shape in cache as in allowed/blocked.**
     `WebServiceZonesApi.cs:68` receives `authoritativeZoneRecords`: `false` for
     cache and `true` for allowed and blocked. In cache the `ttl` is the
     already-composed STRING (`"218 (3m38s)"`) and `responseMetadata`,
     `dnssecRecords`, `eDnsClientSubnet`, `nameServerMetadata` and `lastUsedOn`
     come along; in allowed and blocked the `ttl` is a NUMBER with its own
     `ttlString` apart, and `disabled`, `comments`, `lastModified` and
     `expiryTtl` come along. A stale cache record comes out with `ttl: "0 (0s)"`
     (same source, line 126).

  4. `node` is the cluster node the request is aimed at
     (`DnsWebService.cs:2367`). Empty means "this server". Upstream sends it on
     `cache/list`, `cache/flush`, `cache/delete` and on the `list` of allowed and
     blocked; it does NOT send it on the rest.
*/

export type List = 'cache' | 'allowed' | 'blocked'
export type ListaDominios = Extract<List, 'allowed' | 'blocked'>

/** Metadata of the DNS response that left the record in the cache. */
export interface ResponseMetadata {
  nameServer: string | null
  protocol: string
  datagramSize: string
  roundTripTime: string
}

/** Name-server health, only on cached NS records. */
export interface NameServerMetadata {
  totalQueries: number
  answerRate: string
  smoothedRoundTripTime: string
  smoothedPenaltyRoundTripTime: string
  netRoundTripTime: string
  isMisconfigured: boolean
}

/*
The open index is not laziness: the screen draws `rData` by walking its keys, so
a record type the server adds tomorrow still shows in full instead of
disappearing.
*/
export interface RegistroDns {
  name: string
  nameIdn?: string
  type: string
  /** The string `"218 (3m38s)"` in cache; a number in allowed and blocked. */
  ttl: number | string
  ttlString?: string
  rData: Record<string, unknown>
  dnssecStatus?: string
  // cache only
  dnssecRecords?: string[]
  eDnsClientSubnet?: string
  nameServerMetadata?: NameServerMetadata
  responseMetadata?: ResponseMetadata
  // allowed and blocked only
  disabled?: boolean
  comments?: string
  lastModified?: string
  expiryTtl?: number
  expiryTtlString?: string
  // En ambas
  glueRecords?: string[]
  lastUsedOn?: string
  [field: string]: unknown
}

export interface NodoLista {
  domain: string
  /** Only comes if the domain is an IDN; then it is what gets shown. */
  domainIdn?: string
  zones: string[]
  records: RegistroDns[]
}

/*
`getParentDomain` (other-zones.js:80-94). Returns "" for a single-label domain
—the parent is the root— and `null` only for the root, which is what hides the
[up] link in upstream.
*/
export function dominioPadre(domain: string | null | undefined): string | null {
  if (domain == null || domain === '') return null
  const i = domain.indexOf('.')
  return i === -1 ? '' : domain.substring(i + 1)
}

/*
`cleanTextList` (common.js:326-340). Newline to comma, repeated commas to one,
and out with the ones at the ends. A text of nothing but newlines collapses to
"," and that is why upstream checks for it separately when validating the
import.
*/
export function limpiarLista(text: string): string {
  let t = text.replace(/\n/g, ',')
  while (t.indexOf(',,') !== -1) t = t.replace(/,,/g, ',')
  if (t.startsWith(',')) t = t.substring(1)
  if (t.endsWith(',')) t = t.substring(0, t.length - 1)
  return t
}

/*
`refreshCachedZonesList` / `refreshAllowedZonesList` / `refreshBlockedZonesList`.

Upstream writes `domain.toLowerCase();` WITHOUT assigning the result
(other-zones.js:105, 285, 421). In JavaScript strings are immutable, so that line
does nothing and the domain travels exactly as it was typed. The real behaviour
is replicated, not the intent: the server already takes care of the case.

It returns the `ApiOutcome` with the node already unwrapped instead of
`NodoLista | null` because in upstream a `list` that fails does NOT stay quiet:
the error handler of `HTTPRequest` (common.js) draws the server's `errorMessage`
as an alert. With `null` that text would be lost, and losing a text is losing
behaviour.
*/
export async function listarNodo(
  list: List,
  token: string | null,
  domain: string,
  direction?: 'up',
  node = '',
): Promise<ApiOutcome<NodoLista>> {
  const body: Record<string, string> = { domain, node }
  if (direction != null) body.direction = direction

  const outcome = await apiRequest<{ response: NodoLista }>(`${list}/list`, { token, body })
  return outcome.kind === 'ok' ? { kind: 'ok', data: outcome.data.response } : outcome
}

/** `flushDnsCache` (other-zones.js:20). */
export function vaciarCache(token: string | null, node = ''): Promise<ApiOutcome> {
  return apiRequest('cache/flush', { token, body: { node } })
}

/** `deleteCachedZone` (other-zones.js:52): deletes the node and all its records. */
export function deleteCacheNode(
  token: string | null,
  domain: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('cache/delete', { token, body: { domain, node } })
}

/** `allowZone` / `blockZone`. */
export function addDomain(
  list: ListaDominios,
  token: string | null,
  domain: string,
): Promise<ApiOutcome> {
  return apiRequest(`${list}/add`, { token, body: { domain } })
}

/** `deleteAllowedZone` / `deleteBlockedZone`. */
export function deleteDomain(
  list: ListaDominios,
  token: string | null,
  domain: string,
): Promise<ApiOutcome> {
  return apiRequest(`${list}/delete`, { token, body: { domain } })
}

/** `flushAllowedZone` / `flushBlockedZone`. Sin `node`, a diferencia de cache. */
export function vaciarLista(list: ListaDominios, token: string | null): Promise<ApiOutcome> {
  return apiRequest(`${list}/flush`, { token })
}

/*
`importAllowedZones` / `importBlockedZones`. It goes by POST and the field is
named differently in each list. The server splits on commas
(`WebServiceOtherZonesApi.cs:271`), so the text has to arrive already cleaned by
`limpiarLista`.
*/
export function importarDominios(
  list: ListaDominios,
  token: string | null,
  zones: string,
): Promise<ApiOutcome> {
  const field = list === 'allowed' ? 'allowedZones' : 'blockedZones'
  return apiRequest(`${list}/import`, { token, method: 'POST', body: { [field]: zones } })
}

/*
`exportAllowedZones` / `exportBlockedZones`. The response is a `text/plain` with
`Content-Disposition: attachment` (WebServiceOtherZonesApi.cs:296-306), not JSON:
that is why it cannot go by XHR and is opened in a window with a single-use
token.
*/
export function exportarDominios(
  list: ListaDominios,
  token: string | null,
): Promise<{ ok: boolean; url?: string }> {
  return openDownload(token, `${list}/export`)
}
