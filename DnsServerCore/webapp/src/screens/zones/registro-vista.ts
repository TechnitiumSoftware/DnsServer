import type { ResourceRecord } from '../../api/registros'
import { fechaConAntiguedad, fechaHora, fechaMinuto } from '../../lib/fechas'

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
  | { clase: 'value'; text: string }
  | { clase: 'pairs'; pares: { etiqueta: string; value: string }[] }
  | { clase: 'lines'; lines: string[] }
  | { clase: 'table'; cabeceras: string[]; rows: string[][] }

const s = (v: unknown): string => (v == null ? '' : String(v))

/** `algorithm (algorithmNumber)`, which upstream composes in four places. */
function conNumero(name: unknown, number: unknown): string {
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

export function celdasDeRegistro(r: ResourceRecord): Cell[] {
  const d = r.rData
  const salida: Cell[] = []

  switch (r.type.toUpperCase()) {
    case 'A':
    case 'AAAA':
      salida.push({ clase: 'value', text: s(d.ipAddress) })
      break

    case 'NS': {
      const pares = [{ etiqueta: 'Name Server:', value: s(d.nameServer) }]
      if (r.glueRecords != null) {
        pares.push({ etiqueta: 'Glue Addresses:', value: r.glueRecords.join(', ') })
      }
      salida.push({ clase: 'pairs', pares })
      break
    }

    case 'CNAME':
      salida.push({ clase: 'value', text: s(d.cname) })
      break

    case 'SOA':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Primary Name Server:', value: s(d.primaryNameServer) },
          { etiqueta: 'Responsible Person:', value: s(d.responsiblePerson) },
          { etiqueta: 'Serial:', value: s(d.serial) },
          { etiqueta: 'Refresh:', value: `${s(d.refresh)} (${s(d.refreshString)})` },
          { etiqueta: 'Retry:', value: `${s(d.retry)} (${s(d.retryString)})` },
          { etiqueta: 'Expire:', value: `${s(d.expire)} (${s(d.expireString)})` },
          { etiqueta: 'Minimum:', value: `${s(d.minimum)} (${s(d.minimumString)})` },
          { etiqueta: 'Use Serial Date Scheme:', value: String(d.useSerialDateScheme === true) },
        ],
      })
      break

    case 'PTR':
      salida.push({ clase: 'value', text: s(d.ptrName) })
      break

    case 'MX':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Preference:', value: s(d.preference) },
          { etiqueta: 'Exchange:', value: s(d.exchange) },
        ],
      })
      break

    case 'TXT': {
      // Split, each string goes in quotes and on a line of its own.
      if (d.splitText === true) {
        const cadenas = (d.characterStrings ?? []) as string[]
        salida.push({ clase: 'lines', lines: cadenas.map((c) => `"${escaparTxt(c)}"`) })
      } else {
        salida.push({ clase: 'value', text: escaparTxt(s(d.text)) })
      }
      break
    }

    case 'RP':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Mailbox:', value: s(d.mailbox) },
          { etiqueta: 'TXT Domain:', value: s(d.txtDomain) },
        ],
      })
      break

    case 'SRV':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Priority:', value: s(d.priority) },
          { etiqueta: 'Weight:', value: s(d.weight) },
          { etiqueta: 'Port:', value: s(d.port) },
          { etiqueta: 'Target:', value: s(d.target) },
        ],
      })
      break

    case 'NAPTR':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Order:', value: s(d.order) },
          { etiqueta: 'Preference:', value: s(d.preference) },
          { etiqueta: 'Flags:', value: s(d.flags) },
          { etiqueta: 'Services:', value: s(d.services) },
          { etiqueta: 'Regular Expression:', value: s(d.regexp) },
          { etiqueta: 'Replacement:', value: s(d.replacement) },
        ],
      })
      break

    case 'DNAME':
      salida.push({ clase: 'value', text: s(d.dname) })
      break

    case 'APL': {
      const prefijos = (d.addressPrefixes ?? []) as Record<string, unknown>[]
      salida.push({
        clase: 'table',
        cabeceras: ['Family', 'Negation', 'AFD Part', 'Prefix'],
        rows: prefijos.map((p) => [s(p.addressFamily), s(p.negation), s(p.afdPart), s(p.prefix)]),
      })
      break
    }

    case 'DS':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Key Tag:', value: s(d.keyTag) },
          { etiqueta: 'Algorithm:', value: conNumero(d.algorithm, d.algorithmNumber) },
          { etiqueta: 'Digest Type:', value: conNumero(d.digestType, d.digestTypeNumber) },
          { etiqueta: 'Digest:', value: s(d.digest) },
        ],
      })
      break

    case 'SSHFP':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Algorithm:', value: s(d.algorithm) },
          { etiqueta: 'Fingerprint Type:', value: s(d.fingerprintType) },
          { etiqueta: 'Fingerprint:', value: s(d.fingerprint) },
        ],
      })
      break

    case 'RRSIG':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Type Covered:', value: s(d.typeCovered) },
          { etiqueta: 'Algorithm:', value: conNumero(d.algorithm, d.algorithmNumber) },
          { etiqueta: 'Labels:', value: s(d.labels) },
          { etiqueta: 'Original TTL:', value: s(d.originalTtl) },
          { etiqueta: 'Signature Expiration:', value: s(d.signatureExpiration) },
          { etiqueta: 'Signature Inception:', value: s(d.signatureInception) },
          { etiqueta: 'Key Tag:', value: s(d.keyTag) },
          { etiqueta: "Signer's Name:", value: s(d.signersName) },
          { etiqueta: 'Signature:', value: s(d.signature) },
        ],
      })
      break

    case 'NSEC':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Next Domain Name:', value: s(d.nextDomainName) },
          { etiqueta: 'Types:', value: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'DNSKEY': {
      const pares = [
        { etiqueta: 'Flags:', value: s(d.flags) },
        { etiqueta: 'Protocol:', value: s(d.protocol) },
        { etiqueta: 'Algorithm:', value: conNumero(d.algorithm, d.algorithmNumber) },
        { etiqueta: 'Public Key:', value: s(d.publicKey) },
      ]

      if (d.dnsKeyState != null) {
        let state = s(d.dnsKeyState)
        if (d.dnsKeyStateReadyBy != null) state += ` (ready by: ${fechaMinuto(s(d.dnsKeyStateReadyBy))})`
        else if (d.dnsKeyStateActiveBy != null) state += ` (active by: ${fechaMinuto(s(d.dnsKeyStateActiveBy))})`
        pares.push({ etiqueta: 'Key State:', value: state })
      }

      pares.push({ etiqueta: 'Computed Key Tag:', value: s(d.computedKeyTag) })

      if (d.computedDigests != null) {
        const digests = d.computedDigests as Record<string, unknown>[]
        pares.push({
          etiqueta: 'Computed Digests:',
          value: digests.map((x) => `${s(x.digestType)}: ${s(x.digest)}`).join('\n'),
        })
      }

      salida.push({ clase: 'pairs', pares })
      break
    }

    case 'NSEC3':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { etiqueta: 'Flags:', value: s(d.flags) },
          { etiqueta: 'Iterations:', value: s(d.iterations) },
          { etiqueta: 'Salt:', value: s(d.salt) },
          { etiqueta: 'Next Hashed Owner Name:', value: s(d.nextHashedOwnerName) },
          { etiqueta: 'Types:', value: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'NSEC3PARAM':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { etiqueta: 'Flags:', value: s(d.flags) },
          { etiqueta: 'Iterations:', value: s(d.iterations) },
          { etiqueta: 'Salt:', value: s(d.salt) },
        ],
      })
      break

    case 'TLSA':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Certificate Usage:', value: s(d.certificateUsage) },
          { etiqueta: 'Selector:', value: s(d.selector) },
          { etiqueta: 'Matching Type:', value: s(d.matchingType) },
          { etiqueta: 'Certificate Association Data:', value: s(d.certificateAssociationData) },
        ],
      })
      break

    case 'ZONEMD':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Serial:', value: s(d.serial) },
          { etiqueta: 'Scheme:', value: s(d.scheme) },
          { etiqueta: 'Hash Algorithm:', value: s(d.hashAlgorithm) },
          { etiqueta: 'Digest:', value: s(d.digest) },
        ],
      })
      break

    case 'SVCB':
    case 'HTTPS': {
      const priority = s(d.svcPriority)
      const mode = String(d.svcPriority) === '0' ? ' (alias mode)' : ' (service mode)'
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Priority:', value: priority + mode },
          { etiqueta: 'Target Name:', value: s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName) },
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
        salida.push({ clase: 'table', cabeceras: ['Key', 'Value'], rows })
      }

      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Use Automatic IPv4 Hint:', value: String(d.autoIpv4Hint === true) },
          { etiqueta: 'Use Automatic IPv6 Hint:', value: String(d.autoIpv6Hint === true) },
        ],
      })
      break
    }

    case 'URI':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Priority:', value: s(d.priority) },
          { etiqueta: 'Weight:', value: s(d.weight) },
          { etiqueta: 'URI:', value: s(d.uri) },
        ],
      })
      break

    case 'CAA':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Flags:', value: s(d.flags) },
          { etiqueta: 'Tag:', value: s(d.tag) },
          { etiqueta: 'Authority:', value: s(d.value) },
        ],
      })
      break

    case 'ANAME':
      salida.push({ clase: 'value', text: s(d.aname) })
      break

    case 'FWD': {
      const pares = [
        { etiqueta: 'Protocol:', value: s(d.protocol) },
        { etiqueta: 'Forwarder:', value: s(d.forwarder) },
        { etiqueta: 'Priority:', value: s(d.priority) },
        { etiqueta: 'Enable DNSSEC Validation:', value: String(d.dnssecValidation === true) },
        { etiqueta: 'Proxy Type:', value: s(d.proxyType) },
      ]
      if (d.proxyType === 'Http' || d.proxyType === 'Socks5') {
        pares.push(
          { etiqueta: 'Proxy Address:', value: s(d.proxyAddress) },
          { etiqueta: 'Proxy Port:', value: s(d.proxyPort) },
          { etiqueta: 'Proxy Username:', value: s(d.proxyUsername) },
          { etiqueta: 'Proxy Password:', value: s(d.proxyPassword) },
        )
      }
      salida.push({ clase: 'pairs', pares })
      break
    }

    case 'APP':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'App Name:', value: s(d.appName) },
          { etiqueta: 'Class Path:', value: s(d.classPath) },
          { etiqueta: 'Record Data:', value: s(d.data) },
        ],
      })
      break

    case 'ALIAS':
      salida.push({
        clase: 'pairs',
        pares: [
          { etiqueta: 'Type:', value: s(d.type) },
          { etiqueta: 'Alias:', value: s(d.alias) },
        ],
      })
      break

    default:
      salida.push({ clase: 'pairs', pares: [{ etiqueta: 'RDATA:', value: s(d.value) }] })
      break
  }

  return salida
}

/**
 * The cell's footer: expiry, last used, last modified and comments.
 * `0001-01-01T00:00:00` is "never" and a last modification with that date is
 * **not shown at all**.
 */
export function pieDeRegistro(r: ResourceRecord, ahora?: number): { etiqueta: string; value: string }[] {
  const pares: { etiqueta: string; value: string }[] = []

  if (r.expiryTtl > 0) {
    const caduca = new Date(new Date(r.lastModified).getTime() + r.expiryTtl * 1000)
    pares.push({ etiqueta: 'Expiry TTL:', value: `${r.expiryTtl} (${r.expiryTtlString})` })
    pares.push({ etiqueta: 'Expires On:', value: fechaConAntiguedad(caduca.toISOString(), ahora) })
  }

  // `0001-01-01T00:00:00` is "never", and there upstream does NOT put the age.
  const nunca = r.lastUsedOn === '0001-01-01T00:00:00'
  pares.push({
    etiqueta: 'Last Used:',
    value: nunca ? `${fechaHora(r.lastUsedOn)} (never)` : fechaConAntiguedad(r.lastUsedOn, ahora),
  })

  if (r.lastModified !== '0001-01-01T00:00:00' && r.lastModified !== '0001-01-01T00:00:00Z') {
    pares.push({ etiqueta: 'Last Modified:', value: fechaConAntiguedad(r.lastModified, ahora) })
  }

  return pares
}

/** The name that is shown: relative to the zone, and `@` at the apex. */
export function nombreRelativo(nombreCompleto: string, zone: string): string {
  const name = nombreCompleto === '' ? '.' : nombreCompleto
  const minus = name.toLowerCase()
  if (minus === zone.toLowerCase()) return '@'
  const i = minus.lastIndexOf(`.${zone.toLowerCase()}`)
  return i > -1 ? name.substring(0, i) : name
}

/* ── Acciones por fila ─────────────────────────────────────────────────── */

export interface AccionesDeFila {
  /** La columna entera desaparece. */
  ocultas: boolean
  /** They show but Enable/Disable/Delete are off; Edit is not. */
  editingOnly: boolean
}

/**
 * Which buttons a row offers. It depends on the ZONE type and on the RECORD
 * type, and the three combinations do not overlap the way one would expect: in a
 * catalog zone the SOA can be edited but the rest of the records offer not a
 * single button (zone.js:4195-4232).
 */
export function accionesDeFila(zoneType: string, recordType: string): AccionesDeFila {
  switch (zoneType) {
    case 'Secondary':
    case 'SecondaryForwarder':
    case 'SecondaryCatalog':
    case 'Stub':
      return { ocultas: true, editingOnly: false }

    case 'Catalog':
      return recordType === 'SOA'
        ? { ocultas: false, editingOnly: true }
        : { ocultas: true, editingOnly: false }

    default:
      if (recordType === 'SOA') return { ocultas: false, editingOnly: true }
      if (['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].includes(recordType)) {
        return { ocultas: true, editingOnly: false }
      }
      return { ocultas: false, editingOnly: false }
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
  desdeAhora as haceCuanto,
  fechaConAntiguedad,
} from '../../lib/fechas'
