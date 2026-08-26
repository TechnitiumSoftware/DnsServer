import { apiRequest, type ApiOutcome } from './client'

/*
Los cuatro endpoints de `zones/records/*`: get, add, update y delete.

Se separan de zones.ts porque comparten algo que no comparte nadie más: para
tocar un registro hay que **identificarlo por su contenido**. El servidor no da
identificadores; se le manda el rdata completo del registro tal como está hoy y
él busca cuál es. Eso significa que borrar, deshabilitar y editar tienen que
reconstruir esos parámetros desde el registro que ya se tiene en pantalla, y
esa reconstrucción es la parte más delicada de la fase.

Réplica de zone.js:4707 (add), 5584 (update), 6225 (updateRecordState) y
6400 (delete).

Cuatro cosas que sorprenden y son de upstream:

  1. **Los tres son POST**, con el cuerpo codificado como formulario. `node` es
     el único parámetro que viaja en la query.

  2. **`delete` no tiene caso para CNAME, DNAME, SOA ni APP.** Los cuatro caen
     al `default`, que sólo manda `rdata` si existe — y no existe para ninguno
     de ellos. O sea: para esos tipos el servidor recibe zone+domain+type y
     nada más. No es un olvido nuestro; está así en zone.js:6420-6510.

  3. **`delete` de un NS no manda `glue`; deshabilitarlo sí.** Misma pareja
     de acciones, distinto conjunto de parámetros.

  4. **Deshabilitar un registro es un `records/update`**, no un endpoint
     propio: se reenvía el registro entero con `disable=true`.
*/

export interface Registro {
  name: string
  type: string
  ttl: number
  ttlString: string
  disabled: boolean
  rData: Record<string, unknown>
  dnssecStatus: string
  lastUsedOn: string
  lastModified: string
  expiryTtl: number
  expiryTtlString: string
  comments?: string
  /** Sólo en registros NS con pegamento. */
  glueRecords?: string[]
}

export interface ZonaDeRegistros {
  name: string
  type: string
  disabled: boolean
  /** Una zona Catalog o Forwarder NO lo trae: esos tipos no pueden firmarse. */
  dnssecStatus?: string
  internal?: boolean
  soaSerial?: number
  catalog?: string | null
  notifyFailed?: boolean
  notifyFailedFor?: string[]
}

export interface RegistrosDeZona {
  zone: ZonaDeRegistros
  records: Registro[]
}

/**
 * `zones/records/get`. NO pagina: upstream lo pide con `listZone=true`, recibe
 * todos los registros y pagina en el cliente (zone.js:3079). Verificado contra
 * v15.4: mandarle `recordsPerPage` no cambia nada.
 */
export async function getRecords(
  token: string | null,
  zone: string,
  node = '',
): Promise<RegistrosDeZona | null> {
  const outcome = await apiRequest<{ response: RegistrosDeZona }>('zones/records/get', {
    token,
    body: { domain: zone, zone, listZone: 'true', node },
  })
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return { zone: r.zone, records: r.records ?? [] }
}

export interface RespuestaAlta {
  response: { addedRecord: Registro; zone: ZonaDeRegistros }
}
export interface RespuestaEdicion {
  response: { updatedRecord: Registro; zone: ZonaDeRegistros }
}

export function addRecord(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome<RespuestaAlta>> {
  return apiRequest<RespuestaAlta>(`zones/records/add?node=${encodeURIComponent(node)}`, {
    token,
    method: 'POST',
    body,
  })
}

export function updateRecord(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome<RespuestaEdicion>> {
  return apiRequest<RespuestaEdicion>(`zones/records/update?node=${encodeURIComponent(node)}`, {
    token,
    method: 'POST',
    body,
  })
}

export function deleteRecord(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest(`zones/records/delete?node=${encodeURIComponent(node)}`, {
    token,
    method: 'POST',
    body,
  })
}

/* ── Identidad de un registro ──────────────────────────────────────────── */

const s = (v: unknown): string => (v == null ? '' : String(v))

/**
 * `svcParams` viaja aplanado como `clave|valor|clave|valor`, y una lista vacía
 * viaja como la cadena `"false"` — que es lo que sale de concatenar el booleano
 * al que upstream la reduce (zone.js:5990-6002).
 */
export function aplanarSvcParams(params: unknown): string {
  const obj = (params ?? {}) as Record<string, unknown>
  const partes: string[] = []
  for (const [k, v] of Object.entries(obj)) partes.push(k, s(v))
  return partes.length === 0 ? 'false' : partes.join('|')
}

/** `data-record-glue`: las direcciones unidas por «, » (zone.js:3700-3712). */
export function aplanarGlue(glue: string[] | undefined): string {
  return (glue ?? []).join(', ')
}

/** `data-record-character-strings-base64`: unidas por coma (zone.js:3797-3803). */
export function aplanarCharacterStrings(r: Record<string, unknown>): string {
  const lista = (r.characterStringsBase64 ?? []) as string[]
  return lista.join(',')
}

/**
 * Los parámetros que identifican a un registro existente ante el servidor.
 * Es lo que mandan `deleteRecord` y `updateRecordState`, y también la mitad
 * «vieja» de un `records/update`.
 *
 * `paraBorrado` distingue los dos repartos, que NO son el mismo: al borrar, NS
 * va sin `glue`, y CNAME, DNAME, SOA y APP no aportan nada.
 */
export function identidadRegistro(
  registro: Registro,
  opciones: { paraBorrado?: boolean; updateSvcbHints?: boolean } = {},
): Record<string, string> {
  const d = registro.rData
  const borrado = opciones.paraBorrado === true
  const out: Record<string, string> = {}

  switch (registro.type) {
    case 'A':
    case 'AAAA':
      out.ipAddress = s(d.ipAddress)
      out.updateSvcbHints = String(opciones.updateSvcbHints ?? false)
      break

    case 'NS':
      out.nameServer = s(d.nameServer)
      if (!borrado) out.glue = aplanarGlue(registro.glueRecords)
      break

    case 'CNAME':
      if (!borrado) out.cname = s(d.cname)
      break

    case 'PTR':
      out.ptrName = s(d.ptrName)
      break

    case 'MX':
      out.preference = s(d.preference)
      out.exchange = s(d.exchange)
      break

    case 'TXT':
      out.characterStringsBase64 = aplanarCharacterStrings(d)
      break

    case 'RP':
      out.mailbox = s(d.mailbox)
      out.txtDomain = s(d.txtDomain)
      break

    case 'SRV':
      out.priority = s(d.priority)
      out.weight = s(d.weight)
      out.port = s(d.port)
      out.target = s(d.target)
      break

    case 'NAPTR':
      out.naptrOrder = s(d.order)
      out.naptrPreference = s(d.preference)
      out.naptrFlags = s(d.flags)
      out.naptrServices = s(d.services)
      out.naptrRegexp = s(d.regexp)
      out.naptrReplacement = s(d.replacement)
      break

    case 'DNAME':
      if (!borrado) out.dname = s(d.dname)
      break

    case 'DS':
      out.keyTag = s(d.keyTag)
      out.algorithm = s(d.algorithm)
      out.digestType = s(d.digestType)
      out.digest = s(d.digest)
      break

    case 'SSHFP':
      out.sshfpAlgorithm = s(d.algorithm)
      out.sshfpFingerprintType = s(d.fingerprintType)
      out.sshfpFingerprint = s(d.fingerprint)
      break

    case 'TLSA':
      out.tlsaCertificateUsage = s(d.certificateUsage)
      out.tlsaSelector = s(d.selector)
      out.tlsaMatchingType = s(d.matchingType)
      out.tlsaCertificateAssociationData = s(d.certificateAssociationData)
      break

    case 'SVCB':
    case 'HTTPS':
      out.svcPriority = s(d.svcPriority)
      // Un target vacío se manda como raíz, igual que en la fila (zone.js:4071).
      out.svcTargetName = s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName)
      out.svcParams = aplanarSvcParams(d.svcParams)
      if (!borrado) {
        out.autoIpv4Hint = String(d.autoIpv4Hint === true)
        out.autoIpv6Hint = String(d.autoIpv6Hint === true)
      }
      break

    case 'URI':
      out.uriPriority = s(d.priority)
      out.uriWeight = s(d.weight)
      out.uri = s(d.uri)
      break

    case 'CAA':
      out.flags = s(d.flags)
      out.tag = s(d.tag)
      out.value = s(d.value)
      break

    case 'ANAME':
      out.aname = s(d.aname)
      break

    case 'FWD':
      out.protocol = s(d.protocol)
      out.forwarder = s(d.forwarder)
      if (!borrado) {
        out.forwarderPriority = s(d.priority)
        out.dnssecValidation = String(d.dnssecValidation === true)
        out.proxyType = s(d.proxyType)
        if (d.proxyType === 'Http' || d.proxyType === 'Socks5') {
          out.proxyAddress = s(d.proxyAddress)
          out.proxyPort = s(d.proxyPort)
          out.proxyUsername = s(d.proxyUsername)
          out.proxyPassword = s(d.proxyPassword)
        }
      }
      break

    case 'APP':
      if (!borrado) {
        out.appName = s(d.appName)
        out.classPath = s(d.classPath)
        out.recordData = s(d.data)
      }
      break

    default:
      // `rdata` sólo si el registro lo trae: al borrar, upstream comprueba null.
      if (d.value != null) out.rdata = s(d.value)
      break
  }

  return out
}

/**
 * `zoneHasSvcbAutoHint` (zone.js:4689). Al tocar un A o un AAAA hay que decirle
 * al servidor si tiene que rehacer las pistas automáticas de algún SVCB/HTTPS
 * de la zona. **Sin la lista de registros devuelve `true`**, no `false`: con la
 * zona sin cargar upstream prefiere pedir la actualización.
 */
export function zonaTienePistaSvcbAuto(
  registros: Registro[] | null,
  ipv4: boolean,
  ipv6: boolean,
): boolean {
  if (registros == null) return true

  for (const r of registros) {
    if (r.type !== 'SVCB' && r.type !== 'HTTPS') continue
    const d = r.rData
    if ((d.autoIpv4Hint === true && ipv4) || (d.autoIpv6Hint === true && ipv6)) return true
  }
  return false
}

/**
 * El nombre completo de un registro a partir del sub-dominio escrito en el
 * formulario (zone.js:4713-4725). Vacío es `@`, `@` es la zona, y en la raíz
 * el sub-dominio se cierra con un punto.
 */
export function dominioCompleto(zone: string, subDominio: string): string {
  const sub = subDominio === '' ? '@' : subDominio
  if (sub === '@') return zone
  if (zone === '.') return `${sub}.`
  return `${sub}.${zone}`
}

/**
 * Cuerpo de un `records/delete`: la identidad más zone, domain y type.
 * Un nombre vacío es la raíz (zone.js:6410-6411).
 */
export function cuerpoBorrado(zone: string, registro: Registro): Record<string, string> {
  return {
    zone,
    domain: registro.name === '' ? '.' : registro.name,
    type: registro.type,
    ...identidadRegistro(registro, { paraBorrado: true }),
  }
}

/**
 * Cuerpo del `records/update` que sólo cambia el estado. Reenvía el registro
 * entero —ttl, comentarios y expiración incluidos— con `disable` puesto.
 * `newDomain` no se manda: el nombre no cambia (zone.js:6225-6390).
 */
export function cuerpoCambioDeEstado(
  zone: string,
  registro: Registro,
  deshabilitar: boolean,
  updateSvcbHints: boolean,
): Record<string, string> {
  const domain = registro.name === '' ? '.' : registro.name
  return {
    zone,
    domain,
    type: registro.type,
    ttl: String(registro.ttl),
    disable: String(deshabilitar),
    comments: registro.comments ?? '',
    expiryTtl: String(registro.expiryTtl),
    ...identidadRegistro(registro, { updateSvcbHints }),
  }
}
