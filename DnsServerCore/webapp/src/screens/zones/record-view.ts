import type { ResourceRecord } from '../../api/records'
import { fechaConAntiguedad, fechaHora, fechaMinuto } from '../../lib/dates'

/*
What gets drawn in each record's "Data" cell. A replica of
`getZoneRecordRowHtml` (zone.js:3649-4235), type by type.

The original mixes the drawing and the extraction of the `data-record-*` in the
same function; here there is only the drawing. The other half lives in
`api/registros.ts::identidadRegistro`.

Rules that are replicated and not "fixed":

  · **The colon goes attached or separated depending on the label**, and not
    uniformly: `<b>Preference: </b>` with a space and `<b>Exchange:</b>` without
    it. Here the label is stored already in its final form.

  · **`ipv4hint` and `ipv6hint` are hidden from an SVCB's parameter table** when
    their automatic hint is on: the value is set by the server and showing it
    would confuse.

  · **A DNSKEY without `dnsKeyState` does not show the "Key State" row** instead
    of showing it empty.
*/

export type Cell =
  | { cls: 'value'; text: string }
  | { cls: 'pairs'; pairs: { label: string; value: string }[] }
  | { cls: 'lines'; lines: string[] }
  | { cls: 'table'; headers: string[]; rows: string[][] }

const s = (v: unknown): string => (v == null ? '' : String(v))

/** `algorithm (algorithmNumber)`, which upstream composes in four places. */
function withNumber(name: unknown, number: unknown): string {
  return `${s(name)} (${s(number)})`
}

/**
 * The escaping of a TXT before drawing it: backslashes, carriage returns and
 * newlines are shown as sequences, and quotes are escaped (zone.js:3778 and 3789).
 */
export function escaparTxt(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"')
}

export function recordCells(r: ResourceRecord): Cell[] {
  const d = r.rData
  const output: Cell[] = []

  switch (r.type.toUpperCase()) {
    case 'A':
    case 'AAAA':
      output.push({ cls: 'value', text: s(d.ipAddress) })
      break

    case 'NS': {
      const pairs = [{ label: 'Name Server:', value: s(d.nameServer) }]
      if (r.glueRecords != null) {
        pairs.push({ label: 'Glue Addresses:', value: r.glueRecords.join(', ') })
      }
      output.push({ cls: 'pairs', pairs })
      break
    }

    case 'CNAME':
      output.push({ cls: 'value', text: s(d.cname) })
      break

    case 'SOA':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Primary Name Server:', value: s(d.primaryNameServer) },
          { label: 'Responsible Person:', value: s(d.responsiblePerson) },
          { label: 'Serial:', value: s(d.serial) },
          { label: 'Refresh:', value: `${s(d.refresh)} (${s(d.refreshString)})` },
          { label: 'Retry:', value: `${s(d.retry)} (${s(d.retryString)})` },
          { label: 'Expire:', value: `${s(d.expire)} (${s(d.expireString)})` },
          { label: 'Minimum:', value: `${s(d.minimum)} (${s(d.minimumString)})` },
          { label: 'Use Serial Date Scheme:', value: String(d.useSerialDateScheme === true) },
        ],
      })
      break

    case 'PTR':
      output.push({ cls: 'value', text: s(d.ptrName) })
      break

    case 'MX':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Preference:', value: s(d.preference) },
          { label: 'Exchange:', value: s(d.exchange) },
        ],
      })
      break

    case 'TXT': {
      // Split, each string goes in quotes and on a line of its own.
      if (d.splitText === true) {
        const strings = (d.characterStrings ?? []) as string[]
        output.push({ cls: 'lines', lines: strings.map((c) => `"${escaparTxt(c)}"`) })
      } else {
        output.push({ cls: 'value', text: escaparTxt(s(d.text)) })
      }
      break
    }

    case 'RP':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Mailbox:', value: s(d.mailbox) },
          { label: 'TXT Domain:', value: s(d.txtDomain) },
        ],
      })
      break

    case 'SRV':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Priority:', value: s(d.priority) },
          { label: 'Weight:', value: s(d.weight) },
          { label: 'Port:', value: s(d.port) },
          { label: 'Target:', value: s(d.target) },
        ],
      })
      break

    case 'NAPTR':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Order:', value: s(d.order) },
          { label: 'Preference:', value: s(d.preference) },
          { label: 'Flags:', value: s(d.flags) },
          { label: 'Services:', value: s(d.services) },
          { label: 'Regular Expression:', value: s(d.regexp) },
          { label: 'Replacement:', value: s(d.replacement) },
        ],
      })
      break

    case 'DNAME':
      output.push({ cls: 'value', text: s(d.dname) })
      break

    case 'APL': {
      const prefixes = (d.addressPrefixes ?? []) as Record<string, unknown>[]
      output.push({
        cls: 'table',
        headers: ['Family', 'Negation', 'AFD Part', 'Prefix'],
        rows: prefixes.map((p) => [s(p.addressFamily), s(p.negation), s(p.afdPart), s(p.prefix)]),
      })
      break
    }

    case 'DS':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Key Tag:', value: s(d.keyTag) },
          { label: 'Algorithm:', value: withNumber(d.algorithm, d.algorithmNumber) },
          { label: 'Digest Type:', value: withNumber(d.digestType, d.digestTypeNumber) },
          { label: 'Digest:', value: s(d.digest) },
        ],
      })
      break

    case 'SSHFP':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Algorithm:', value: s(d.algorithm) },
          { label: 'Fingerprint Type:', value: s(d.fingerprintType) },
          { label: 'Fingerprint:', value: s(d.fingerprint) },
        ],
      })
      break

    case 'RRSIG':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Type Covered:', value: s(d.typeCovered) },
          { label: 'Algorithm:', value: withNumber(d.algorithm, d.algorithmNumber) },
          { label: 'Labels:', value: s(d.labels) },
          { label: 'Original TTL:', value: s(d.originalTtl) },
          { label: 'Signature Expiration:', value: s(d.signatureExpiration) },
          { label: 'Signature Inception:', value: s(d.signatureInception) },
          { label: 'Key Tag:', value: s(d.keyTag) },
          { label: "Signer's Name:", value: s(d.signersName) },
          { label: 'Signature:', value: s(d.signature) },
        ],
      })
      break

    case 'NSEC':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Next Domain Name:', value: s(d.nextDomainName) },
          { label: 'Types:', value: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'DNSKEY': {
      const pairs = [
        { label: 'Flags:', value: s(d.flags) },
        { label: 'Protocol:', value: s(d.protocol) },
        { label: 'Algorithm:', value: withNumber(d.algorithm, d.algorithmNumber) },
        { label: 'Public Key:', value: s(d.publicKey) },
      ]

      if (d.dnsKeyState != null) {
        let state = s(d.dnsKeyState)
        if (d.dnsKeyStateReadyBy != null) state += ` (ready by: ${fechaMinuto(s(d.dnsKeyStateReadyBy))})`
        else if (d.dnsKeyStateActiveBy != null) state += ` (active by: ${fechaMinuto(s(d.dnsKeyStateActiveBy))})`
        pairs.push({ label: 'Key State:', value: state })
      }

      pairs.push({ label: 'Computed Key Tag:', value: s(d.computedKeyTag) })

      if (d.computedDigests != null) {
        const digests = d.computedDigests as Record<string, unknown>[]
        pairs.push({
          label: 'Computed Digests:',
          value: digests.map((x) => `${s(x.digestType)}: ${s(x.digest)}`).join('\n'),
        })
      }

      output.push({ cls: 'pairs', pairs })
      break
    }

    case 'NSEC3':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { label: 'Flags:', value: s(d.flags) },
          { label: 'Iterations:', value: s(d.iterations) },
          { label: 'Salt:', value: s(d.salt) },
          { label: 'Next Hashed Owner Name:', value: s(d.nextHashedOwnerName) },
          { label: 'Types:', value: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'NSEC3PARAM':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { label: 'Flags:', value: s(d.flags) },
          { label: 'Iterations:', value: s(d.iterations) },
          { label: 'Salt:', value: s(d.salt) },
        ],
      })
      break

    case 'TLSA':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Certificate Usage:', value: s(d.certificateUsage) },
          { label: 'Selector:', value: s(d.selector) },
          { label: 'Matching Type:', value: s(d.matchingType) },
          { label: 'Certificate Association Data:', value: s(d.certificateAssociationData) },
        ],
      })
      break

    case 'ZONEMD':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Serial:', value: s(d.serial) },
          { label: 'Scheme:', value: s(d.scheme) },
          { label: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { label: 'Digest:', value: s(d.digest) },
        ],
      })
      break

    case 'SVCB':
    case 'HTTPS': {
      const priority = s(d.svcPriority)
      const mode = String(d.svcPriority) === '0' ? ' (alias mode)' : ' (service mode)'
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Priority:', value: priority + mode },
          { label: 'Target Name:', value: s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName) },
        ],
      })

      const params = (d.svcParams ?? {}) as Record<string, unknown>
      const rows: string[][] = []
      for (const [key, value] of Object.entries(params)) {
        if (key === 'ipv4hint' && d.autoIpv4Hint === true) continue
        if (key === 'ipv6hint' && d.autoIpv6Hint === true) continue
        rows.push([key, s(value)])
      }
      if (Object.keys(params).length > 0) {
        output.push({ cls: 'table', headers: ['Key', 'Value'], rows })
      }

      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Use Automatic IPv4 Hint:', value: String(d.autoIpv4Hint === true) },
          { label: 'Use Automatic IPv6 Hint:', value: String(d.autoIpv6Hint === true) },
        ],
      })
      break
    }

    case 'URI':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Priority:', value: s(d.priority) },
          { label: 'Weight:', value: s(d.weight) },
          { label: 'URI:', value: s(d.uri) },
        ],
      })
      break

    case 'CAA':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Flags:', value: s(d.flags) },
          { label: 'Tag:', value: s(d.tag) },
          { label: 'Authority:', value: s(d.value) },
        ],
      })
      break

    case 'ANAME':
      output.push({ cls: 'value', text: s(d.aname) })
      break

    case 'FWD': {
      const pairs = [
        { label: 'Protocol:', value: s(d.protocol) },
        { label: 'Forwarder:', value: s(d.forwarder) },
        { label: 'Priority:', value: s(d.priority) },
        { label: 'Enable DNSSEC Validation:', value: String(d.dnssecValidation === true) },
        { label: 'Proxy Type:', value: s(d.proxyType) },
      ]
      if (d.proxyType === 'Http' || d.proxyType === 'Socks5') {
        pairs.push(
          { label: 'Proxy Address:', value: s(d.proxyAddress) },
          { label: 'Proxy Port:', value: s(d.proxyPort) },
          { label: 'Proxy Username:', value: s(d.proxyUsername) },
          { label: 'Proxy Password:', value: s(d.proxyPassword) },
        )
      }
      output.push({ cls: 'pairs', pairs })
      break
    }

    case 'APP':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'App Name:', value: s(d.appName) },
          { label: 'Class Path:', value: s(d.classPath) },
          { label: 'Record Data:', value: s(d.data) },
        ],
      })
      break

    case 'ALIAS':
      output.push({
        cls: 'pairs',
        pairs: [
          { label: 'Type:', value: s(d.type) },
          { label: 'Alias:', value: s(d.alias) },
        ],
      })
      break

    default:
      output.push({ cls: 'pairs', pairs: [{ label: 'RDATA:', value: s(d.value) }] })
      break
  }

  return output
}

/**
 * The cell's footer: expiry, last used, last modified and comments.
 * `0001-01-01T00:00:00` is "never" and a last modification with that date is
 * **not shown at all**.
 */
export function recordFooter(r: ResourceRecord, now?: number): { label: string; value: string }[] {
  const pairs: { label: string; value: string }[] = []

  if (r.expiryTtl > 0) {
    const expires = new Date(new Date(r.lastModified).getTime() + r.expiryTtl * 1000)
    pairs.push({ label: 'Expiry TTL:', value: `${r.expiryTtl} (${r.expiryTtlString})` })
    pairs.push({ label: 'Expires On:', value: fechaConAntiguedad(expires.toISOString(), now) })
  }

  // `0001-01-01T00:00:00` is "never", and there upstream does NOT put the age.
  const nunca = r.lastUsedOn === '0001-01-01T00:00:00'
  pairs.push({
    label: 'Last Used:',
    value: nunca ? `${fechaHora(r.lastUsedOn)} (never)` : fechaConAntiguedad(r.lastUsedOn, now),
  })

  if (r.lastModified !== '0001-01-01T00:00:00' && r.lastModified !== '0001-01-01T00:00:00Z') {
    pairs.push({ label: 'Last Modified:', value: fechaConAntiguedad(r.lastModified, now) })
  }

  return pairs
}

/** The name that is shown: relative to the zone, and `@` at the apex. */
export function nombreRelativo(nombreCompleto: string, zone: string): string {
  const name = nombreCompleto === '' ? '.' : nombreCompleto
  const minus = name.toLowerCase()
  if (minus === zone.toLowerCase()) return '@'
  const i = minus.lastIndexOf(`.${zone.toLowerCase()}`)
  return i > -1 ? name.substring(0, i) : name
}

/* ── Per-row actions ──────────────────────────────────────────────────── */

export interface RowActions {
  /** La columna entera desaparece. */
  hidden: boolean
  /** They show but Enable/Disable/Delete are off; Edit is not. */
  editingOnly: boolean
}

/**
 * Which buttons a row offers. It depends on the ZONE type and on the RECORD
 * type, and the three combinations do not overlap the way one would expect: in a
 * catalog zone the SOA can be edited but the rest of the records offer not a
 * single button (zone.js:4195-4232).
 */
export function rowActions(zoneType: string, recordType: string): RowActions {
  switch (zoneType) {
    case 'Secondary':
    case 'SecondaryForwarder':
    case 'SecondaryCatalog':
    case 'Stub':
      return { hidden: true, editingOnly: false }

    case 'Catalog':
      return recordType === 'SOA'
        ? { hidden: false, editingOnly: true }
        : { hidden: true, editingOnly: false }

    default:
      if (recordType === 'SOA') return { hidden: false, editingOnly: true }
      if (['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].includes(recordType)) {
        return { hidden: true, editingOnly: false }
      }
      return { hidden: false, editingOnly: false }
  }
}

/** The five types "Hide DNSSEC Records" hides (zone.js:3446-3460). */
export const DNSSEC_TYPES = ['RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM']

export function ocultarDnssec(records: ResourceRecord[]): ResourceRecord[] {
  return records.filter((r) => !DNSSEC_TYPES.includes(r.type.toUpperCase()))
}

/* ── Fechas ───────────────────────────────────────────────────────────── */

/*
The dates were unified into `src/lib/fechas.ts` when integrating phases 4, 8 and
9: all three had written their own copy of `moment().format()` and `fromNow()`.
They are re-exported under the names this screen uses so as not to touch its
calls.
*/
export {
  fechaMinuto as fechaCorta,
  fechaHora as fechaLarga,
  fromNow as howLongAgo,
  fechaConAntiguedad,
} from '../../lib/dates'
