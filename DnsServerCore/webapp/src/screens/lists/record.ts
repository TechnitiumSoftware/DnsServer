import type { DnsRecord } from '../../api/zonelists'

/*
From raw JSON to table rows.

Upstream dumps `JSON.stringify(records, null, 2)` inside a `<pre>`
(other-zones.js:157, 335, 471). Here it is drawn as a table, and that forces one
rule: **not a single field of the JSON may disappear along the way**. That is why
nothing here carries a whitelist of record types. Whatever keys arrive are walked
through, given a readable name, and anything unrecognised comes out all the same
with its humanised name. If tomorrow the server adds a field or a new record
type, it appears on its own.

Three pairs of keys the server emits together and that are merged into one line
so as not to repeat the same datum twice (WebServiceZonesApi.cs:68-860):

  `algorithm` + `algorithmNumber`   -> "RSASHA256 (8)"
  `refresh`   + `refreshString`     -> "900 (15m)"
  `nameServer`+ `nameServerIdn`     -> "mañana.test (xn--maana-pta.test)"
*/

export interface Entry {
  key: string
  value: string
  /** A DNSKEY public key blows the width apart: the screen truncates it. */
  long: boolean
}

const LONG = 64

/** Names upstream and the design use that do not come from humanising the key. */
const LABELS: Record<string, string> = {
  ipAddress: 'IP Address',
  nameServer: 'Name Server',
  cname: 'CNAME',
  dname: 'DNAME',
  ptrName: 'PTR Name',
  primaryNameServer: 'Primary NS',
  responsiblePerson: 'Responsible',
  publicKey: 'Public key',
  keyTag: 'Key tag',
  computedKeyTag: 'Key tag',
  eDnsClientSubnet: 'EDNS Client Subnet',
  rdata: 'Data',
  uri: 'URI',
  svcPriority: 'SvcPriority',
  targetName: 'Target Name',
}

/** `algorithmNumber` -> "Algorithm number"; `flags` -> "Flags". */
function humanise(key: string): string {
  if (LABELS[key]) return LABELS[key]
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

function text(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') return String(v)
  return JSON.stringify(v)
}

function entry(key: string, value: string): Entry {
  return { key, value, long: value.length > LONG }
}

const SUFFIXES = ['String', 'Number', 'Idn'] as const

/**
 * Turns a flat object into key/value rows, merging the `x`/`xString`,
 * `x`/`xNumber` and `x`/`xIdn` pairs.
 */
function rows(obj: Record<string, unknown>): Entry[] {
  const output: Entry[] = []

  for (const key of Object.keys(obj)) {
    // The derived keys are drawn next to their base, not on their own.
    const derived = SUFFIXES.some(
      (s) => key.endsWith(s) && key.length > s.length && key.slice(0, -s.length) in obj,
    )
    if (derived) continue

    let value = text(obj[key])

    const idn = obj[`${key}Idn`]
    if (idn != null) {
      // The Unicode is the readable one; the ASCII is what travels down the wire.
      value = `${text(idn)} (${value})`
    } else {
      const composed = obj[`${key}String`] ?? obj[`${key}Number`]
      if (composed != null) value = `${value} (${text(composed)})`
    }

    output.push(entry(humanise(key), value))
  }

  return output
}

export function rdataEntries(rData: Record<string, unknown>): Entry[] {
  return rows(rData ?? {})
}

/*
The TTL arrives in two different shapes depending on the list (see
`zonelists.ts`). It is normalised to the pair the design asks for: the number,
and its human form beside it.
*/
export function ttlPartido(r: DnsRecord): { value: string; human: string } {
  if (typeof r.ttl === 'string') {
    const m = /^(\S+)\s+\((.*)\)$/.exec(r.ttl)
    return m ? { value: m[1], human: m[2] } : { value: r.ttl, human: '' }
  }
  return { value: String(r.ttl), human: r.ttlString ?? '' }
}

/*
`0001-01-01T00:00:00` is .NET's `default(DateTime)`: it means "never", not a date
in year 1. And it is trimmed to minutes WITHOUT converting the time zone, because
the server emits UTC and converting would be changing the datum; the full stamp
is kept in the cell's `title`.
*/
export function fechaCorta(iso: string | undefined | null): string | null {
  if (!iso || iso.startsWith('0001-01-01')) return null
  return iso.slice(0, 16).replace('T', ' ')
}

/*
The grey line of each row. In cache it carries where the record came from; in
allowed and blocked, the record's state in the zone.
*/
export function meta(r: DnsRecord): string[] {
  const parts: string[] = []

  if (r.disabled) parts.push('disabled')

  const rm = r.responseMetadata
  if (rm) {
    parts.push(`via ${rm.nameServer ?? '—'}`)
    if (rm.protocol) parts.push(rm.protocol)
    if (rm.datagramSize) parts.push(rm.datagramSize)
    if (rm.roundTripTime) parts.push(rm.roundTripTime)
  } else if (r.dnssecStatus) {
    // In cache the DNSSEC state has a column of its own; here it does not, so it goes here.
    parts.push(`DNSSEC ${r.dnssecStatus}`)
  }

  // The vocabulary is upstream's: "Last Modified", "Last Used" and "(never)"
  // (zone.js:4179-4188), here on a single line instead of three.
  const modified = fechaCorta(r.lastModified)
  if (modified) parts.push(`modified ${modified}`)

  const used = fechaCorta(r.lastUsedOn)
  parts.push(used ? `used ${used}` : 'never used')

  if (r.expiryTtl != null) {
    parts.push(r.expiryTtl > 0 ? `expires in ${r.expiryTtlString ?? r.expiryTtl}` : 'no expiry')
  }

  return parts
}

/*
Everything none of the functions above draws. It is the net that guarantees no
field of the JSON falls through: it starts from the record's real keys and
subtracts the ones that already have a place.
*/
const ALREADY_DRAWN = new Set([
  'name',
  'nameIdn',
  'type',
  'ttl',
  'ttlString',
  'rData',
  'dnssecStatus',
  'dnssecRecords',
  'glueRecords',
  'responseMetadata',
  'nameServerMetadata',
  'lastUsedOn',
  'lastModified',
  'expiryTtl',
  'expiryTtlString',
  'disabled',
])

export function extras(r: DnsRecord): Entry[] {
  const rest: Record<string, unknown> = {}
  for (const key of Object.keys(r)) {
    if (!ALREADY_DRAWN.has(key)) rest[key] = r[key]
  }

  const output = rows(rest)

  // The name server's health is an object: it is spread out field by field
  // so it reads, instead of landing as JSON inside a cell.
  if (r.nameServerMetadata) {
    output.push(...rows(r.nameServerMetadata as unknown as Record<string, unknown>))
  }

  return output
}
