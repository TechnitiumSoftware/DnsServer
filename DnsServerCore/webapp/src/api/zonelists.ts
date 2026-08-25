import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'

/*
Las tres listas de dominios que NO son zonas de autoridad: `cache`, `allowed` y
`blocked`. Quince endpoints, todos en `other-zones.js`.

Las tres se navegan igual —un árbol de dominios, un nodo cada vez— y sus tres
endpoints `list` devuelven la misma envoltura: `domain`, `domainIdn`, `zones` y
`records`.
Por eso comparten módulo y comparten pantalla.

Cuatro cosas del servidor que no se deducen mirando el JavaScript de upstream y
que gobiernan la pantalla:

  1. **El servidor puede DEVOLVER UN DOMINIO DISTINTO DEL PEDIDO.**
     `WebServiceOtherZonesApi.cs:88-120` baja sola por la cadena mientras el nodo
     no tenga registros y tenga exactamente un hijo: pedir `org` con un único
     `example.org` debajo devuelve `example.org` y SUS registros. Con
     `direction=up` la misma condición hace subir. Por eso quien pinta el árbol
     debe usar SIEMPRE `response.domain`, nunca el dominio que pidió.

  2. **`zones` trae nombres de dominio COMPLETOS**, no etiquetas: el servidor
     concatena `subZone + "." + domain` (misma fuente, líneas 133-146) y los
     convierte a Unicode si son IDN. Se navegan tal cual, sin recomponer nada.

  3. **`records` NO tiene la misma forma en cache que en allowed/blocked.**
     `WebServiceZonesApi.cs:68` recibe `authoritativeZoneRecords`: `false` para
     cache y `true` para allowed y blocked. En cache el `ttl` es la CADENA ya
     compuesta (`"218 (3m38s)"`) y vienen `responseMetadata`, `dnssecRecords`,
     `eDnsClientSubnet`, `nameServerMetadata` y `lastUsedOn`; en allowed y
     blocked el `ttl` es un NÚMERO con su `ttlString` aparte, y vienen
     `disabled`, `comments`, `lastModified` y `expiryTtl`. Un registro de cache
     rancio sale con `ttl: "0 (0s)"` (misma fuente, línea 126).

  4. `node` es el nodo del cluster al que se dirige la petición
     (`DnsWebService.cs:2367`). Vacío significa «este servidor». Upstream lo
     manda en `cache/list`, `cache/flush`, `cache/delete` y en los `list` de
     allowed y blocked; NO lo manda en el resto.
*/

export type Lista = 'cache' | 'allowed' | 'blocked'
export type ListaDominios = Extract<Lista, 'allowed' | 'blocked'>

/** Metadatos de la respuesta DNS que dejó el registro en cache. */
export interface ResponseMetadata {
  nameServer: string | null
  protocol: string
  datagramSize: string
  roundTripTime: string
}

/** Salud del servidor de nombres, sólo en registros NS de cache. */
export interface NameServerMetadata {
  totalQueries: number
  answerRate: string
  smoothedRoundTripTime: string
  smoothedPenaltyRoundTripTime: string
  netRoundTripTime: string
  isMisconfigured: boolean
}

/*
El índice abierto no es dejadez: la pantalla pinta `rData` recorriendo sus
claves, y así un tipo de registro que el servidor añada mañana se sigue viendo
entero en vez de desaparecer.
*/
export interface RegistroDns {
  name: string
  nameIdn?: string
  type: string
  /** Cadena `"218 (3m38s)"` en cache; número en allowed y blocked. */
  ttl: number | string
  ttlString?: string
  rData: Record<string, unknown>
  dnssecStatus?: string
  // Sólo cache
  dnssecRecords?: string[]
  eDnsClientSubnet?: string
  nameServerMetadata?: NameServerMetadata
  responseMetadata?: ResponseMetadata
  // Sólo allowed y blocked
  disabled?: boolean
  comments?: string
  lastModified?: string
  expiryTtl?: number
  expiryTtlString?: string
  // En ambas
  glueRecords?: string[]
  lastUsedOn?: string
  [campo: string]: unknown
}

export interface NodoLista {
  domain: string
  /** Sólo viene si el dominio es IDN; entonces es lo que se muestra. */
  domainIdn?: string
  zones: string[]
  records: RegistroDns[]
}

/*
`getParentDomain` (other-zones.js:80-94). Devuelve "" para un dominio de una sola
etiqueta —el padre es la raíz— y `null` sólo para la raíz, que es lo que en
upstream oculta el enlace [up].
*/
export function dominioPadre(domain: string | null | undefined): string | null {
  if (domain == null || domain === '') return null
  const i = domain.indexOf('.')
  return i === -1 ? '' : domain.substring(i + 1)
}

/*
`cleanTextList` (common.js:326-340). Salto de línea a coma, comas repetidas a
una, y fuera la de los extremos. Un texto de sólo saltos de línea colapsa a ","
y por eso upstream lo comprueba aparte al validar el import.
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

Upstream escribe `domain.toLowerCase();` SIN asignar el resultado
(other-zones.js:105, 285, 421). En JavaScript las cadenas son inmutables, así
que esa línea no hace nada y el dominio viaja tal cual se escribió. Se replica
el comportamiento real, no la intención: del caso ya se encarga el servidor.

Devuelve el `ApiOutcome` con el nodo ya desenvuelto en vez de `NodoLista | null`
porque en upstream un `list` que falla NO se queda callado: el manejador de
errores de `HTTPRequest` (common.js) pinta `errorMessage` del servidor como
aviso. Con `null` ese texto se perdería, y perder un texto es perder
comportamiento.
*/
export async function listarNodo(
  lista: Lista,
  token: string | null,
  domain: string,
  direction?: 'up',
  node = '',
): Promise<ApiOutcome<NodoLista>> {
  const body: Record<string, string> = { domain, node }
  if (direction != null) body.direction = direction

  const outcome = await apiRequest<{ response: NodoLista }>(`${lista}/list`, { token, body })
  return outcome.kind === 'ok' ? { kind: 'ok', data: outcome.data.response } : outcome
}

/** `flushDnsCache` (other-zones.js:20). */
export function vaciarCache(token: string | null, node = ''): Promise<ApiOutcome> {
  return apiRequest('cache/flush', { token, body: { node } })
}

/** `deleteCachedZone` (other-zones.js:52): borra el nodo y todos sus registros. */
export function borrarNodoCache(
  token: string | null,
  domain: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('cache/delete', { token, body: { domain, node } })
}

/** `allowZone` / `blockZone`. */
export function anadirDominio(
  lista: ListaDominios,
  token: string | null,
  domain: string,
): Promise<ApiOutcome> {
  return apiRequest(`${lista}/add`, { token, body: { domain } })
}

/** `deleteAllowedZone` / `deleteBlockedZone`. */
export function borrarDominio(
  lista: ListaDominios,
  token: string | null,
  domain: string,
): Promise<ApiOutcome> {
  return apiRequest(`${lista}/delete`, { token, body: { domain } })
}

/** `flushAllowedZone` / `flushBlockedZone`. Sin `node`, a diferencia de cache. */
export function vaciarLista(lista: ListaDominios, token: string | null): Promise<ApiOutcome> {
  return apiRequest(`${lista}/flush`, { token })
}

/*
`importAllowedZones` / `importBlockedZones`. Va por POST y el campo se llama
distinto en cada lista. El servidor parte por comas
(`WebServiceOtherZonesApi.cs:271`), así que el texto ya tiene que venir limpio
con `limpiarLista`.
*/
export function importarDominios(
  lista: ListaDominios,
  token: string | null,
  zonas: string,
): Promise<ApiOutcome> {
  const campo = lista === 'allowed' ? 'allowedZones' : 'blockedZones'
  return apiRequest(`${lista}/import`, { token, method: 'POST', body: { [campo]: zonas } })
}

/*
`exportAllowedZones` / `exportBlockedZones`. La respuesta es un `text/plain` con
`Content-Disposition: attachment` (WebServiceOtherZonesApi.cs:296-306), no JSON:
por eso no puede ir por XHR y se abre en una ventana con un token de un solo uso.
*/
export function exportarDominios(
  lista: ListaDominios,
  token: string | null,
): Promise<{ ok: boolean; url?: string }> {
  return openDownload(token, `${lista}/export`)
}
