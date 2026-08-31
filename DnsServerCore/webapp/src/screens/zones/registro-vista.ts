import type { Registro } from '../../api/registros'
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

export type Celda =
  | { clase: 'valor'; texto: string }
  | { clase: 'pares'; pares: { etiqueta: string; valor: string }[] }
  | { clase: 'lineas'; lineas: string[] }
  | { clase: 'tabla'; cabeceras: string[]; filas: string[][] }

const s = (v: unknown): string => (v == null ? '' : String(v))

/** `algorithm (algorithmNumber)`, which upstream composes in four places. */
function conNumero(nombre: unknown, numero: unknown): string {
  return `${s(nombre)} (${s(numero)})`
}

/**
 * The escaping of a TXT before drawing it: backslashes, carriage returns and
 * newlines are shown as sequences, and quotes are escaped (zone.js:3778 and 3789).
 */
export function escaparTxt(texto: string): string {
  return texto
    .replace(/\\/g, '\\\\')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"')
}

export function celdasDeRegistro(r: Registro): Celda[] {
  const d = r.rData
  const salida: Celda[] = []

  switch (r.type.toUpperCase()) {
    case 'A':
    case 'AAAA':
      salida.push({ clase: 'valor', texto: s(d.ipAddress) })
      break

    case 'NS': {
      const pares = [{ etiqueta: 'Name Server:', valor: s(d.nameServer) }]
      if (r.glueRecords != null) {
        pares.push({ etiqueta: 'Glue Addresses:', valor: r.glueRecords.join(', ') })
      }
      salida.push({ clase: 'pares', pares })
      break
    }

    case 'CNAME':
      salida.push({ clase: 'valor', texto: s(d.cname) })
      break

    case 'SOA':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Primary Name Server:', valor: s(d.primaryNameServer) },
          { etiqueta: 'Responsible Person:', valor: s(d.responsiblePerson) },
          { etiqueta: 'Serial:', valor: s(d.serial) },
          { etiqueta: 'Refresh:', valor: `${s(d.refresh)} (${s(d.refreshString)})` },
          { etiqueta: 'Retry:', valor: `${s(d.retry)} (${s(d.retryString)})` },
          { etiqueta: 'Expire:', valor: `${s(d.expire)} (${s(d.expireString)})` },
          { etiqueta: 'Minimum:', valor: `${s(d.minimum)} (${s(d.minimumString)})` },
          { etiqueta: 'Use Serial Date Scheme:', valor: String(d.useSerialDateScheme === true) },
        ],
      })
      break

    case 'PTR':
      salida.push({ clase: 'valor', texto: s(d.ptrName) })
      break

    case 'MX':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Preference:', valor: s(d.preference) },
          { etiqueta: 'Exchange:', valor: s(d.exchange) },
        ],
      })
      break

    case 'TXT': {
      // Split, each string goes in quotes and on a line of its own.
      if (d.splitText === true) {
        const cadenas = (d.characterStrings ?? []) as string[]
        salida.push({ clase: 'lineas', lineas: cadenas.map((c) => `"${escaparTxt(c)}"`) })
      } else {
        salida.push({ clase: 'valor', texto: escaparTxt(s(d.text)) })
      }
      break
    }

    case 'RP':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Mailbox:', valor: s(d.mailbox) },
          { etiqueta: 'TXT Domain:', valor: s(d.txtDomain) },
        ],
      })
      break

    case 'SRV':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Priority:', valor: s(d.priority) },
          { etiqueta: 'Weight:', valor: s(d.weight) },
          { etiqueta: 'Port:', valor: s(d.port) },
          { etiqueta: 'Target:', valor: s(d.target) },
        ],
      })
      break

    case 'NAPTR':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Order:', valor: s(d.order) },
          { etiqueta: 'Preference:', valor: s(d.preference) },
          { etiqueta: 'Flags:', valor: s(d.flags) },
          { etiqueta: 'Services:', valor: s(d.services) },
          { etiqueta: 'Regular Expression:', valor: s(d.regexp) },
          { etiqueta: 'Replacement:', valor: s(d.replacement) },
        ],
      })
      break

    case 'DNAME':
      salida.push({ clase: 'valor', texto: s(d.dname) })
      break

    case 'APL': {
      const prefijos = (d.addressPrefixes ?? []) as Record<string, unknown>[]
      salida.push({
        clase: 'tabla',
        cabeceras: ['Family', 'Negation', 'AFD Part', 'Prefix'],
        filas: prefijos.map((p) => [s(p.addressFamily), s(p.negation), s(p.afdPart), s(p.prefix)]),
      })
      break
    }

    case 'DS':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Key Tag:', valor: s(d.keyTag) },
          { etiqueta: 'Algorithm:', valor: conNumero(d.algorithm, d.algorithmNumber) },
          { etiqueta: 'Digest Type:', valor: conNumero(d.digestType, d.digestTypeNumber) },
          { etiqueta: 'Digest:', valor: s(d.digest) },
        ],
      })
      break

    case 'SSHFP':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Algorithm:', valor: s(d.algorithm) },
          { etiqueta: 'Fingerprint Type:', valor: s(d.fingerprintType) },
          { etiqueta: 'Fingerprint:', valor: s(d.fingerprint) },
        ],
      })
      break

    case 'RRSIG':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Type Covered:', valor: s(d.typeCovered) },
          { etiqueta: 'Algorithm:', valor: conNumero(d.algorithm, d.algorithmNumber) },
          { etiqueta: 'Labels:', valor: s(d.labels) },
          { etiqueta: 'Original TTL:', valor: s(d.originalTtl) },
          { etiqueta: 'Signature Expiration:', valor: s(d.signatureExpiration) },
          { etiqueta: 'Signature Inception:', valor: s(d.signatureInception) },
          { etiqueta: 'Key Tag:', valor: s(d.keyTag) },
          { etiqueta: "Signer's Name:", valor: s(d.signersName) },
          { etiqueta: 'Signature:', valor: s(d.signature) },
        ],
      })
      break

    case 'NSEC':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Next Domain Name:', valor: s(d.nextDomainName) },
          { etiqueta: 'Types:', valor: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'DNSKEY': {
      const pares = [
        { etiqueta: 'Flags:', valor: s(d.flags) },
        { etiqueta: 'Protocol:', valor: s(d.protocol) },
        { etiqueta: 'Algorithm:', valor: conNumero(d.algorithm, d.algorithmNumber) },
        { etiqueta: 'Public Key:', valor: s(d.publicKey) },
      ]

      if (d.dnsKeyState != null) {
        let estado = s(d.dnsKeyState)
        if (d.dnsKeyStateReadyBy != null) estado += ` (ready by: ${fechaMinuto(s(d.dnsKeyStateReadyBy))})`
        else if (d.dnsKeyStateActiveBy != null) estado += ` (active by: ${fechaMinuto(s(d.dnsKeyStateActiveBy))})`
        pares.push({ etiqueta: 'Key State:', valor: estado })
      }

      pares.push({ etiqueta: 'Computed Key Tag:', valor: s(d.computedKeyTag) })

      if (d.computedDigests != null) {
        const digests = d.computedDigests as Record<string, unknown>[]
        pares.push({
          etiqueta: 'Computed Digests:',
          valor: digests.map((x) => `${s(x.digestType)}: ${s(x.digest)}`).join('\n'),
        })
      }

      salida.push({ clase: 'pares', pares })
      break
    }

    case 'NSEC3':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Hash Algorithm:', valor: s(d.hashAlgorithm) },
          { etiqueta: 'Flags:', valor: s(d.flags) },
          { etiqueta: 'Iterations:', valor: s(d.iterations) },
          { etiqueta: 'Salt:', valor: s(d.salt) },
          { etiqueta: 'Next Hashed Owner Name:', valor: s(d.nextHashedOwnerName) },
          { etiqueta: 'Types:', valor: ((d.types ?? []) as string[]).join(', ') },
        ],
      })
      break

    case 'NSEC3PARAM':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Hash Algorithm:', valor: s(d.hashAlgorithm) },
          { etiqueta: 'Flags:', valor: s(d.flags) },
          { etiqueta: 'Iterations:', valor: s(d.iterations) },
          { etiqueta: 'Salt:', valor: s(d.salt) },
        ],
      })
      break

    case 'TLSA':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Certificate Usage:', valor: s(d.certificateUsage) },
          { etiqueta: 'Selector:', valor: s(d.selector) },
          { etiqueta: 'Matching Type:', valor: s(d.matchingType) },
          { etiqueta: 'Certificate Association Data:', valor: s(d.certificateAssociationData) },
        ],
      })
      break

    case 'ZONEMD':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Serial:', valor: s(d.serial) },
          { etiqueta: 'Scheme:', valor: s(d.scheme) },
          { etiqueta: 'Hash Algorithm:', valor: s(d.hashAlgorithm) },
          { etiqueta: 'Digest:', valor: s(d.digest) },
        ],
      })
      break

    case 'SVCB':
    case 'HTTPS': {
      const prioridad = s(d.svcPriority)
      const modo = String(d.svcPriority) === '0' ? ' (alias mode)' : ' (service mode)'
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Priority:', valor: prioridad + modo },
          { etiqueta: 'Target Name:', valor: s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName) },
        ],
      })

      const params = (d.svcParams ?? {}) as Record<string, unknown>
      const filas: string[][] = []
      for (const [clave, valor] of Object.entries(params)) {
        if (clave === 'ipv4hint' && d.autoIpv4Hint === true) continue
        if (clave === 'ipv6hint' && d.autoIpv6Hint === true) continue
        filas.push([clave, s(valor)])
      }
      if (Object.keys(params).length > 0) {
        salida.push({ clase: 'tabla', cabeceras: ['Key', 'Value'], filas })
      }

      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Use Automatic IPv4 Hint:', valor: String(d.autoIpv4Hint === true) },
          { etiqueta: 'Use Automatic IPv6 Hint:', valor: String(d.autoIpv6Hint === true) },
        ],
      })
      break
    }

    case 'URI':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Priority:', valor: s(d.priority) },
          { etiqueta: 'Weight:', valor: s(d.weight) },
          { etiqueta: 'URI:', valor: s(d.uri) },
        ],
      })
      break

    case 'CAA':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Flags:', valor: s(d.flags) },
          { etiqueta: 'Tag:', valor: s(d.tag) },
          { etiqueta: 'Authority:', valor: s(d.value) },
        ],
      })
      break

    case 'ANAME':
      salida.push({ clase: 'valor', texto: s(d.aname) })
      break

    case 'FWD': {
      const pares = [
        { etiqueta: 'Protocol:', valor: s(d.protocol) },
        { etiqueta: 'Forwarder:', valor: s(d.forwarder) },
        { etiqueta: 'Priority:', valor: s(d.priority) },
        { etiqueta: 'Enable DNSSEC Validation:', valor: String(d.dnssecValidation === true) },
        { etiqueta: 'Proxy Type:', valor: s(d.proxyType) },
      ]
      if (d.proxyType === 'Http' || d.proxyType === 'Socks5') {
        pares.push(
          { etiqueta: 'Proxy Address:', valor: s(d.proxyAddress) },
          { etiqueta: 'Proxy Port:', valor: s(d.proxyPort) },
          { etiqueta: 'Proxy Username:', valor: s(d.proxyUsername) },
          { etiqueta: 'Proxy Password:', valor: s(d.proxyPassword) },
        )
      }
      salida.push({ clase: 'pares', pares })
      break
    }

    case 'APP':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'App Name:', valor: s(d.appName) },
          { etiqueta: 'Class Path:', valor: s(d.classPath) },
          { etiqueta: 'Record Data:', valor: s(d.data) },
        ],
      })
      break

    case 'ALIAS':
      salida.push({
        clase: 'pares',
        pares: [
          { etiqueta: 'Type:', valor: s(d.type) },
          { etiqueta: 'Alias:', valor: s(d.alias) },
        ],
      })
      break

    default:
      salida.push({ clase: 'pares', pares: [{ etiqueta: 'RDATA:', valor: s(d.value) }] })
      break
  }

  return salida
}

/**
 * The cell's footer: expiry, last used, last modified and comments.
 * `0001-01-01T00:00:00` is "never" and a last modification with that date is
 * **not shown at all**.
 */
export function pieDeRegistro(r: Registro, ahora?: number): { etiqueta: string; valor: string }[] {
  const pares: { etiqueta: string; valor: string }[] = []

  if (r.expiryTtl > 0) {
    const caduca = new Date(new Date(r.lastModified).getTime() + r.expiryTtl * 1000)
    pares.push({ etiqueta: 'Expiry TTL:', valor: `${r.expiryTtl} (${r.expiryTtlString})` })
    pares.push({ etiqueta: 'Expires On:', valor: fechaConAntiguedad(caduca.toISOString(), ahora) })
  }

  // `0001-01-01T00:00:00` is "never", and there upstream does NOT put the age.
  const nunca = r.lastUsedOn === '0001-01-01T00:00:00'
  pares.push({
    etiqueta: 'Last Used:',
    valor: nunca ? `${fechaHora(r.lastUsedOn)} (never)` : fechaConAntiguedad(r.lastUsedOn, ahora),
  })

  if (r.lastModified !== '0001-01-01T00:00:00' && r.lastModified !== '0001-01-01T00:00:00Z') {
    pares.push({ etiqueta: 'Last Modified:', valor: fechaConAntiguedad(r.lastModified, ahora) })
  }

  return pares
}

/** The name that is shown: relative to the zone, and `@` at the apex. */
export function nombreRelativo(nombreCompleto: string, zone: string): string {
  const nombre = nombreCompleto === '' ? '.' : nombreCompleto
  const minus = nombre.toLowerCase()
  if (minus === zone.toLowerCase()) return '@'
  const i = minus.lastIndexOf(`.${zone.toLowerCase()}`)
  return i > -1 ? nombre.substring(0, i) : nombre
}

/* ── Acciones por fila ─────────────────────────────────────────────────── */

export interface AccionesDeFila {
  /** La columna entera desaparece. */
  ocultas: boolean
  /** They show but Enable/Disable/Delete are off; Edit is not. */
  soloEdicion: boolean
}

/**
 * Which buttons a row offers. It depends on the ZONE type and on the RECORD
 * type, and the three combinations do not overlap the way one would expect: in a
 * catalog zone the SOA can be edited but the rest of the records offer not a
 * single button (zone.js:4195-4232).
 */
export function accionesDeFila(tipoZona: string, tipoRegistro: string): AccionesDeFila {
  switch (tipoZona) {
    case 'Secondary':
    case 'SecondaryForwarder':
    case 'SecondaryCatalog':
    case 'Stub':
      return { ocultas: true, soloEdicion: false }

    case 'Catalog':
      return tipoRegistro === 'SOA'
        ? { ocultas: false, soloEdicion: true }
        : { ocultas: true, soloEdicion: false }

    default:
      if (tipoRegistro === 'SOA') return { ocultas: false, soloEdicion: true }
      if (['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].includes(tipoRegistro)) {
        return { ocultas: true, soloEdicion: false }
      }
      return { ocultas: false, soloEdicion: false }
  }
}

/** The five types "Hide DNSSEC Records" hides (zone.js:3446-3460). */
export const TIPOS_DNSSEC = ['RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM']

export function ocultarDnssec(registros: Registro[]): Registro[] {
  return registros.filter((r) => !TIPOS_DNSSEC.includes(r.type.toUpperCase()))
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
