import { apiRequest, type ApiOutcome } from './client'

/*
The four endpoints of `zones/records/*`: get, add, update and delete.

They are kept apart from zones.ts because they share something nobody else does:
to touch a record you have to **identify it by its content**. The server hands
out no identifiers; it is sent the record's full rdata exactly as it stands today
and it looks up which one it is. That means delete, disable and edit all have to
rebuild those parameters from the record already on screen, and that rebuilding
is the most delicate part of the phase.

A replica of zone.js:4707 (add), 5584 (update), 6225 (updateRecordState) and
6400 (delete).

Four things that come as a surprise and belong to upstream:

  1. **All three are POST**, with the body encoded as a form. `node` is the only
     parameter that travels in the query.

  2. **`delete` has no case for CNAME, DNAME, SOA or APP.** All four fall to the
     `default`, which only sends `rdata` if it exists — and it exists for none of
     them. That is: for those types the server receives zone+domain+type and
     nothing else. It is not an oversight of ours; that is how it is in
     zone.js:6420-6510.

  3. **Deleting an NS does not send `glue`; disabling it does.** Same pair of
     actions, different set of parameters.

  4. **Disabling a record is a `records/update`**, not an endpoint of its own:
     the whole record is resent with `disable=true`.
*/

export interface ResourceRecord {
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
  /** Only on NS records with glue. */
  glueRecords?: string[]
}

export interface ZoneDetails {
  name: string
  type: string
  disabled: boolean
  /** A Catalog or Forwarder zone does NOT bring it: those types cannot be signed. */
  dnssecStatus?: string
  internal?: boolean
  soaSerial?: number
  catalog?: string | null
  notifyFailed?: boolean
  notifyFailedFor?: string[]
}

export interface ZoneRecordsData {
  zone: ZoneDetails
  records: ResourceRecord[]
}

/**
 * `zones/records/get`. It does NOT paginate: upstream asks for it with
 * `listZone=true`, receives every record and paginates on the client
 * (zone.js:3079). Verified against v15.4: sending it `recordsPerPage` changes
 * nothing.
 */
export async function getRecords(
  token: string | null,
  zone: string,
  node = '',
): Promise<ZoneRecordsData | null> {
  const outcome = await apiRequest<{ response: ZoneRecordsData }>('zones/records/get', {
    token,
    body: { domain: zone, zone, listZone: 'true', node },
  })
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return { zone: r.zone, records: r.records ?? [] }
}

export interface RespuestaAlta {
  response: { addedRecord: ResourceRecord; zone: ZoneDetails }
}
export interface EditResponse {
  response: { updatedRecord: ResourceRecord; zone: ZoneDetails }
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
): Promise<ApiOutcome<EditResponse>> {
  return apiRequest<EditResponse>(`zones/records/update?node=${encodeURIComponent(node)}`, {
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
 * `svcParams` travels flattened as `key|value|key|value`, and an empty list
 * travels as the string `"false"` — which is what comes out of concatenating the
 * boolean upstream reduces it to (zone.js:5990-6002).
 */
export function aplanarSvcParams(params: unknown): string {
  const obj = (params ?? {}) as Record<string, unknown>
  const parts: string[] = []
  for (const [k, v] of Object.entries(obj)) parts.push(k, s(v))
  return parts.length === 0 ? 'false' : parts.join('|')
}

/** `data-record-glue`: the addresses joined by ", " (zone.js:3700-3712). */
export function aplanarGlue(glue: string[] | undefined): string {
  return (glue ?? []).join(', ')
}

/** `data-record-character-strings-base64`: unidas por coma (zone.js:3797-3803). */
export function aplanarCharacterStrings(r: Record<string, unknown>): string {
  const list = (r.characterStringsBase64 ?? []) as string[]
  return list.join(',')
}

/**
 * The parameters that identify an existing record to the server. It is what
 * `deleteRecord` and `updateRecordState` send, and also the "old" half of a
 * `records/update`.
 *
 * `paraBorrado` tells the two splits apart, and they are NOT the same: when
 * deleting, NS goes without `glue`, and CNAME, DNAME, SOA and APP contribute
 * nothing.
 */
export function recordIdentity(
  record: ResourceRecord,
  options: { forDeletion?: boolean; updateSvcbHints?: boolean } = {},
): Record<string, string> {
  const d = record.rData
  const deletion = options.forDeletion === true
  const out: Record<string, string> = {}

  switch (record.type) {
    case 'A':
    case 'AAAA':
      out.ipAddress = s(d.ipAddress)
      out.updateSvcbHints = String(options.updateSvcbHints ?? false)
      break

    case 'NS':
      out.nameServer = s(d.nameServer)
      if (!deletion) out.glue = aplanarGlue(record.glueRecords)
      break

    case 'CNAME':
      if (!deletion) out.cname = s(d.cname)
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
      if (!deletion) out.dname = s(d.dname)
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
      // An empty target is sent as the root, same as in the row (zone.js:4071).
      out.svcTargetName = s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName)
      out.svcParams = aplanarSvcParams(d.svcParams)
      if (!deletion) {
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
      if (!deletion) {
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
      if (!deletion) {
        out.appName = s(d.appName)
        out.classPath = s(d.classPath)
        out.recordData = s(d.data)
      }
      break

    default:
      // `rdata` only if the record brings it: when deleting, upstream checks for null.
      if (d.value != null) out.rdata = s(d.value)
      break
  }

  return out
}

/**
 * `zoneHasSvcbAutoHint` (zone.js:4689). When touching an A or an AAAA the server
 * has to be told whether it must redo the automatic hints of any SVCB/HTTPS in
 * the zone. **Without the record list it returns `true`**, not `false`: with the
 * zone unloaded upstream would rather ask for the update.
 */
export function zoneHasSvcbAutoHint(
  records: ResourceRecord[] | null,
  ipv4: boolean,
  ipv6: boolean,
): boolean {
  if (records == null) return true

  for (const r of records) {
    if (r.type !== 'SVCB' && r.type !== 'HTTPS') continue
    const d = r.rData
    if ((d.autoIpv4Hint === true && ipv4) || (d.autoIpv6Hint === true && ipv6)) return true
  }
  return false
}

/**
 * A record's full name from the sub-domain typed into the form
 * (zone.js:4713-4725). Empty is `@`, `@` is the zone, and at the root the
 * sub-domain is closed with a dot.
 */
export function fullDomain(zone: string, subDomain: string): string {
  const sub = subDomain === '' ? '@' : subDomain
  if (sub === '@') return zone
  if (zone === '.') return `${sub}.`
  return `${sub}.${zone}`
}

/**
 * The body of a `records/delete`: the identity plus zone, domain and type.
 * An empty name is the root (zone.js:6410-6411).
 */
export function cuerpoBorrado(zone: string, record: ResourceRecord): Record<string, string> {
  return {
    zone,
    domain: record.name === '' ? '.' : record.name,
    type: record.type,
    ...recordIdentity(record, { forDeletion: true }),
  }
}

/**
 * The body of the `records/update` that only changes the state. It resends the
 * whole record —ttl, comments and expiry included— with `disable` set.
 * `newDomain` is not sent: the name does not change (zone.js:6225-6390).
 */
export function cuerpoCambioDeEstado(
  zone: string,
  record: ResourceRecord,
  disable: boolean,
  updateSvcbHints: boolean,
): Record<string, string> {
  const domain = record.name === '' ? '.' : record.name
  return {
    zone,
    domain,
    type: record.type,
    ttl: String(record.ttl),
    disable: String(disable),
    comments: record.comments ?? '',
    expiryTtl: String(record.expiryTtl),
    ...recordIdentity(record, { updateSvcbHints }),
  }
}
