import { dominioCompleto, identidadRegistro, type ResourceRecord } from '../../api/registros'
import { limpiarLista } from '../../api/zonelists'
import { serializeTable } from '../../lib/tabla-serie'

/*
The "Add / Edit Record" form and its validation: a replica of `addRecord`
(zone.js:4707) and `updateRecord` (5584), the two longest `switch` of the old
console.

They are together because they are the SAME form, and splitting them would have
doubled the places to get it wrong. What changes between add and edit is:

  1. The add sends `overwrite`; the edit sends `disable` and `newDomain`.
  2. The edit sends, besides the new value, **the old value** of nearly every
     type, because the server identifies the record by its content.
  3. The alert texts say "to add the record" or "to update the record"… except a
     handful that are identical in both (SRV, NAPTR, URI, CAA). They are copied
     one by one; they are not generated from a template.
  4. **SOA can only be edited**, never created. **APP does not validate on edit**
     and its name and class cannot be changed: only its `recordData`.
  5. **The check for a TLSA's full PEM certificate only exists when adding.** On
     editing, that same value goes through untouched.
*/

export type RecordMode = 'add' | 'update'

/** The 23 types of the dropdown, in upstream's order (index.html). */
export const RECORD_TYPES = [
  'A', 'NS', 'SOA', 'CNAME', 'PTR', 'MX', 'TXT', 'RP', 'AAAA', 'SRV', 'NAPTR',
  'DNAME', 'DS', 'SSHFP', 'TLSA', 'SVCB', 'HTTPS', 'URI', 'CAA', 'ANAME',
  'FWD', 'APP', 'Unknown',
] as const

export interface ParametroSvcb {
  key: string
  value: string
}

export interface FormularioRegistro {
  name: string
  type: string
  ttl: string
  overwrite: boolean
  comments: string
  expiryTtl: string

  /** The "Value" field shared by A, AAAA, CNAME, PTR, DNAME, ANAME and Unknown. */
  value: string
  ptr: boolean
  createPtrZone: boolean

  nsNameServer: string
  nsGlue: string

  soaPrimaryNameServer: string
  soaResponsiblePerson: string
  soaSerial: string
  soaRefresh: string
  soaRetry: string
  soaExpire: string
  soaMinimum: string
  soaUseSerialDateScheme: boolean

  mxPreference: string
  mxExchange: string

  txt: string
  txtSplitText: boolean

  rpMailbox: string
  rpTxtDomain: string

  srvPriority: string
  srvWeight: string
  srvPort: string
  srvTarget: string

  naptrOrder: string
  naptrPreference: string
  naptrFlags: string
  naptrServices: string
  naptrRegexp: string
  naptrReplacement: string

  dsKeyTag: string
  dsAlgorithm: string
  dsDigestType: string
  dsDigest: string

  sshfpAlgorithm: string
  sshfpFingerprintType: string
  sshfpFingerprint: string

  tlsaCertificateUsage: string
  tlsaSelector: string
  tlsaMatchingType: string
  tlsaCertificateAssociationData: string

  svcbPriority: string
  svcbTargetName: string
  svcbParams: ParametroSvcb[]
  svcbAutoIpv4Hint: boolean
  svcbAutoIpv6Hint: boolean

  uriPriority: string
  uriWeight: string
  uri: string

  caaFlags: string
  caaTag: string
  caaValue: string

  forwarderProtocol: string
  forwarder: string
  forwarderPriority: string
  forwarderDnssecValidation: boolean
  proxyType: string
  proxyAddress: string
  proxyPort: string
  proxyUsername: string
  proxyPassword: string

  appName: string
  classPath: string
  recordData: string

  unknownType: string
}

export function formularioVacio(): FormularioRegistro {
  return {
    name: '', type: 'A', ttl: '3600', overwrite: false, comments: '', expiryTtl: '',
    value: '', ptr: false, createPtrZone: false,
    nsNameServer: '', nsGlue: '',
    soaPrimaryNameServer: '', soaResponsiblePerson: '', soaSerial: '', soaRefresh: '',
    soaRetry: '', soaExpire: '', soaMinimum: '', soaUseSerialDateScheme: false,
    mxPreference: '', mxExchange: '',
    txt: '', txtSplitText: false,
    rpMailbox: '', rpTxtDomain: '',
    srvPriority: '', srvWeight: '', srvPort: '', srvTarget: '',
    naptrOrder: '', naptrPreference: '', naptrFlags: '', naptrServices: '',
    naptrRegexp: '', naptrReplacement: '',
    dsKeyTag: '', dsAlgorithm: '', dsDigestType: '', dsDigest: '',
    sshfpAlgorithm: '', sshfpFingerprintType: '', sshfpFingerprint: '',
    tlsaCertificateUsage: '', tlsaSelector: '', tlsaMatchingType: '',
    tlsaCertificateAssociationData: '',
    svcbPriority: '', svcbTargetName: '', svcbParams: [], svcbAutoIpv4Hint: false,
    svcbAutoIpv6Hint: false,
    uriPriority: '', uriWeight: '', uri: '',
    caaFlags: '', caaTag: '', caaValue: '',
    forwarderProtocol: 'Udp', forwarder: '', forwarderPriority: '',
    forwarderDnssecValidation: false, proxyType: 'DefaultProxy', proxyAddress: '',
    proxyPort: '', proxyUsername: '', proxyPassword: '',
    appName: '', classPath: '', recordData: '',
    unknownType: '',
  }
}

const s = (v: unknown): string => (v == null ? '' : String(v))

/** Fills the form with an existing record, for editing. */
export function formularioDesdeRegistro(r: ResourceRecord, zone: string): FormularioRegistro {
  const f = formularioVacio()
  const d = r.rData

  f.name = nombreRelativo(r.name, zone)
  f.type = r.type
  f.ttl = String(r.ttl)
  f.comments = r.comments ?? ''
  f.expiryTtl = String(r.expiryTtl)

  switch (r.type.toUpperCase()) {
    case 'A':
    case 'AAAA':
      f.value = s(d.ipAddress)
      break
    case 'NS':
      f.nsNameServer = s(d.nameServer)
      f.nsGlue = (r.glueRecords ?? []).join('\n')
      break
    case 'CNAME':
      f.value = s(d.cname)
      break
    case 'SOA':
      f.soaPrimaryNameServer = s(d.primaryNameServer)
      f.soaResponsiblePerson = s(d.responsiblePerson)
      f.soaSerial = s(d.serial)
      f.soaRefresh = s(d.refresh)
      f.soaRetry = s(d.retry)
      f.soaExpire = s(d.expire)
      f.soaMinimum = s(d.minimum)
      f.soaUseSerialDateScheme = d.useSerialDateScheme === true
      break
    case 'PTR':
      f.value = s(d.ptrName)
      break
    case 'MX':
      f.mxPreference = s(d.preference)
      f.mxExchange = s(d.exchange)
      break
    case 'TXT':
      f.txt = s(d.text)
      f.txtSplitText = d.splitText === true
      break
    case 'RP':
      f.rpMailbox = s(d.mailbox)
      f.rpTxtDomain = s(d.txtDomain)
      break
    case 'SRV':
      f.srvPriority = s(d.priority)
      f.srvWeight = s(d.weight)
      f.srvPort = s(d.port)
      f.srvTarget = s(d.target)
      break
    case 'NAPTR':
      f.naptrOrder = s(d.order)
      f.naptrPreference = s(d.preference)
      f.naptrFlags = s(d.flags)
      f.naptrServices = s(d.services)
      f.naptrRegexp = s(d.regexp)
      f.naptrReplacement = s(d.replacement)
      break
    case 'DNAME':
      f.value = s(d.dname)
      break
    case 'DS':
      f.dsKeyTag = s(d.keyTag)
      f.dsAlgorithm = s(d.algorithm)
      f.dsDigestType = s(d.digestType)
      f.dsDigest = s(d.digest)
      break
    case 'SSHFP':
      f.sshfpAlgorithm = s(d.algorithm)
      f.sshfpFingerprintType = s(d.fingerprintType)
      f.sshfpFingerprint = s(d.fingerprint)
      break
    case 'TLSA':
      f.tlsaCertificateUsage = s(d.certificateUsage)
      f.tlsaSelector = s(d.selector)
      f.tlsaMatchingType = s(d.matchingType)
      f.tlsaCertificateAssociationData = s(d.certificateAssociationData)
      break
    case 'SVCB':
    case 'HTTPS': {
      f.svcbPriority = s(d.svcPriority)
      f.svcbTargetName = s(d.svcTargetName) === '' ? '.' : s(d.svcTargetName)
      const params = (d.svcParams ?? {}) as Record<string, unknown>
      f.svcbParams = Object.entries(params).map(([key, value]) => ({ key, value: s(value) }))
      f.svcbAutoIpv4Hint = d.autoIpv4Hint === true
      f.svcbAutoIpv6Hint = d.autoIpv6Hint === true
      break
    }
    case 'URI':
      f.uriPriority = s(d.priority)
      f.uriWeight = s(d.weight)
      f.uri = s(d.uri)
      break
    case 'CAA':
      f.caaFlags = s(d.flags)
      f.caaTag = s(d.tag)
      f.caaValue = s(d.value)
      break
    case 'ANAME':
      f.value = s(d.aname)
      break
    case 'FWD':
      f.forwarderProtocol = s(d.protocol)
      f.forwarder = s(d.forwarder)
      f.forwarderPriority = s(d.priority)
      f.forwarderDnssecValidation = d.dnssecValidation === true
      f.proxyType = s(d.proxyType)
      f.proxyAddress = s(d.proxyAddress)
      f.proxyPort = s(d.proxyPort)
      f.proxyUsername = s(d.proxyUsername)
      f.proxyPassword = s(d.proxyPassword)
      break
    case 'APP':
      f.appName = s(d.appName)
      f.classPath = s(d.classPath)
      f.recordData = s(d.data)
      break
    default:
      f.unknownType = r.type
      f.value = s(d.value)
      break
  }

  return f
}

/** A local copy so as not to import circularly from `registro-vista`. */
function nombreRelativo(nombreCompleto: string, zone: string): string {
  const name = nombreCompleto === '' ? '.' : nombreCompleto
  const minus = name.toLowerCase()
  if (minus === zone.toLowerCase()) return '@'
  const i = minus.lastIndexOf(`.${zone.toLowerCase()}`)
  return i > -1 ? name.substring(0, i) : name
}

export interface RecordError {
  title: string
  text: string
  /** Which field receives the focus, just as upstream does. */
  field: keyof FormularioRegistro
}

export type ResultadoRegistro =
  | { error: RecordError }
  | { body: Record<string, string> }

export interface ContextoRegistro {
  zone: string
  mode: RecordMode
  /** Only on edit: the record being touched. */
  original?: ResourceRecord
  /** `zoneHasSvcbAutoHint`: whether some SVCB's hints have to be redone. */
  updateSvcbHints: boolean
}

/*
`serializeTableData` with 2 columns for an SVCB's parameters. The algorithm lives
in `lib/tabla-serie`, shared by the five screens with an editable table.

An empty list travels as the string "false", not as an empty string, and that
part does belong here: the shared function returns the empty one and the caller
decides.
*/
export function serializeSvcParams(
  rows: ParametroSvcb[],
): { value: string } | { error: RecordError } {
  const r = serializeTable(
    rows.map((row) =>
      [row.key, row.value].map((value) => ({ type: 'text' as const, value })),
    ),
  )
  if (!r.ok) {
    return { error: { title: r.failure.title, text: r.failure.text, field: 'svcbParams' } }
  }
  return { value: r.value.length === 0 ? 'false' : r.value }
}

export function construirCuerpoRegistro(
  f: FormularioRegistro,
  ctx: ContextoRegistro,
): ResultadoRegistro {
  const alta = ctx.mode === 'add'
  const verbo = alta ? 'add' : 'update'
  const missing = (text: string, field: keyof FormularioRegistro): ResultadoRegistro => ({
    error: { title: 'Missing!', text, field },
  })

  // The identity of the record being edited: the "old" half of the body.
  const old = ctx.original
    ? identidadRegistro(ctx.original, { updateSvcbHints: ctx.updateSvcbHints })
    : {}

  const p: Record<string, string> = {}
  let type = f.type

  switch (f.type.toUpperCase()) {
    case 'A':
    case 'AAAA': {
      if (f.value === '') return missing(`Please enter an IP address to ${verbo} the record.`, 'value')
      if (alta) p.ipAddress = f.value
      else {
        p.ipAddress = old.ipAddress ?? ''
        p.newIpAddress = f.value
      }
      p.ptr = String(f.ptr)
      p.createPtrZone = String(f.createPtrZone)
      p.updateSvcbHints = String(ctx.updateSvcbHints)
      break
    }

    case 'NS': {
      if (f.nsNameServer === '') {
        return missing(`Please enter a name server to ${verbo} the record.`, 'nsNameServer')
      }
      if (alta) p.nameServer = f.nsNameServer
      else {
        p.nameServer = old.nameServer ?? ''
        p.newNameServer = f.nsNameServer
      }
      p.glue = limpiarLista(f.nsGlue)
      break
    }

    case 'CNAME': {
      // The name alert is identical on add and edit, with that enormous
      // explanation about ANAME that is copied whole.
      if (f.name === '' || f.name === '@') {
        return missing(
          "Please enter a name for the CNAME record since DNS protocol does not allow CNAME at zone's apex. If you need CNAME like function at the zone's apex then use ANAME record instead.",
          'name',
        )
      }
      if (f.value === '') return missing(`Please enter a domain name to ${verbo} the record.`, 'value')
      p.cname = f.value
      break
    }

    case 'SOA': {
      // It only exists on edit: there is no add branch for SOA.
      if (f.soaPrimaryNameServer === '') {
        return missing('Please enter a value for primary name server.', 'soaPrimaryNameServer')
      }
      if (f.soaResponsiblePerson === '') {
        return missing('Please enter a value for responsible person.', 'soaResponsiblePerson')
      }
      if (f.soaSerial === '') return missing('Please enter a value for serial.', 'soaSerial')
      if (f.soaRefresh === '') return missing('Please enter a value for refresh.', 'soaRefresh')
      if (f.soaRetry === '') return missing('Please enter a value for retry.', 'soaRetry')
      if (f.soaExpire === '') return missing('Please enter a value for expire.', 'soaExpire')
      if (f.soaMinimum === '') return missing('Please enter a value for minimum.', 'soaMinimum')

      p.primaryNameServer = f.soaPrimaryNameServer
      p.responsiblePerson = f.soaResponsiblePerson
      p.serial = f.soaSerial
      p.refresh = f.soaRefresh
      p.retry = f.soaRetry
      p.expire = f.soaExpire
      p.minimum = f.soaMinimum
      p.useSerialDateScheme = String(f.soaUseSerialDateScheme)
      break
    }

    case 'PTR': {
      if (f.value === '') return missing(`Please enter a suitable value to ${verbo} the record.`, 'value')
      if (alta) p.ptrName = f.value
      else {
        p.ptrName = old.ptrName ?? ''
        p.newPtrName = f.value
      }
      break
    }

    case 'MX': {
      // An empty preference falls to 1, it does not error.
      const preferencia = f.mxPreference === '' ? '1' : f.mxPreference
      if (f.mxExchange === '') {
        return missing(`Please enter a mail exchange domain name to ${verbo} the record.`, 'mxExchange')
      }
      if (alta) {
        p.preference = preferencia
        p.exchange = f.mxExchange
      } else {
        p.preference = old.preference ?? ''
        p.newPreference = preferencia
        p.exchange = old.exchange ?? ''
        p.newExchange = f.mxExchange
      }
      break
    }

    case 'TXT': {
      if (f.txt === '') return missing(`Please enter a suitable value to ${verbo} the record.`, 'txt')
      if (alta) {
        p.text = f.txt
        p.splitText = String(f.txtSplitText)
      } else {
        p.characterStringsBase64 = old.characterStringsBase64 ?? ''
        p.newText = f.txt
        p.newSplitText = String(f.txtSplitText)
      }
      break
    }

    case 'RP': {
      // Both empties fall to the root; there is no alert at all.
      const buzon = f.rpMailbox === '' ? '.' : f.rpMailbox
      const dominioTxt = f.rpTxtDomain === '' ? '.' : f.rpTxtDomain
      if (alta) {
        p.mailbox = buzon
        p.txtDomain = dominioTxt
      } else {
        p.mailbox = old.mailbox ?? ''
        p.newMailbox = buzon
        p.txtDomain = old.txtDomain ?? ''
        p.newTxtDomain = dominioTxt
      }
      break
    }

    case 'SRV': {
      if (f.name === '') {
        return missing('Please enter a name that includes service and protocol labels.', 'name')
      }
      if (f.srvPriority === '') return missing('Please enter a suitable priority.', 'srvPriority')
      if (f.srvWeight === '') return missing('Please enter a suitable weight.', 'srvWeight')
      if (f.srvPort === '') return missing('Please enter a suitable port number.', 'srvPort')
      if (f.srvTarget === '') {
        return missing('Please enter a suitable value into the target field.', 'srvTarget')
      }

      if (alta) {
        p.priority = f.srvPriority
        p.weight = f.srvWeight
        p.port = f.srvPort
        p.target = f.srvTarget
      } else {
        p.priority = old.priority ?? ''
        p.newPriority = f.srvPriority
        p.weight = old.weight ?? ''
        p.newWeight = f.srvWeight
        p.port = old.port ?? ''
        p.newPort = f.srvPort
        p.target = old.target ?? ''
        p.newTarget = f.srvTarget
      }
      break
    }

    case 'NAPTR': {
      if (f.naptrOrder === '') return missing('Please enter a suitable order.', 'naptrOrder')
      if (f.naptrPreference === '') return missing('Please enter a suitable preference.', 'naptrPreference')

      if (alta) {
        p.naptrOrder = f.naptrOrder
        p.naptrPreference = f.naptrPreference
        p.naptrFlags = f.naptrFlags
        p.naptrServices = f.naptrServices
        p.naptrRegexp = f.naptrRegexp
        p.naptrReplacement = f.naptrReplacement
      } else {
        // Only on EDIT does an empty replacement fall to the root. On add, it does not.
        p.naptrOrder = old.naptrOrder ?? ''
        p.naptrNewOrder = f.naptrOrder
        p.naptrPreference = old.naptrPreference ?? ''
        p.naptrNewPreference = f.naptrPreference
        p.naptrFlags = old.naptrFlags ?? ''
        p.naptrNewFlags = f.naptrFlags
        p.naptrServices = old.naptrServices ?? ''
        p.naptrNewServices = f.naptrServices
        p.naptrRegexp = old.naptrRegexp ?? ''
        p.naptrNewRegexp = f.naptrRegexp
        p.naptrReplacement = old.naptrReplacement ?? ''
        p.naptrNewReplacement = f.naptrReplacement === '' ? '.' : f.naptrReplacement
      }
      break
    }

    case 'DNAME': {
      if (f.value === '') return missing(`Please enter a domain name to ${verbo} the record.`, 'value')
      p.dname = f.value
      break
    }

    case 'DS': {
      if (f.name === '' || f.name === '@') {
        return missing('Please enter a name for the DS record.', 'name')
      }
      if (f.dsKeyTag === '') {
        return missing(`Please enter the Key Tag value to ${verbo} the record.`, 'dsKeyTag')
      }
      if (f.dsAlgorithm === '') {
        return missing(`Please select an DNSSEC algorithm to ${verbo} the record.`, 'dsAlgorithm')
      }
      if (f.dsDigestType === '') {
        return missing(`Please select a Digest Type to ${verbo} the record.`, 'dsDigestType')
      }
      if (f.dsDigest === '') {
        return missing(
          `Please enter the Digest hash in hex string format to ${verbo} the record.`,
          'dsDigest',
        )
      }

      if (alta) {
        p.keyTag = f.dsKeyTag
        p.algorithm = f.dsAlgorithm
        p.digestType = f.dsDigestType
        p.digest = f.dsDigest
      } else {
        p.keyTag = old.keyTag ?? ''
        p.algorithm = old.algorithm ?? ''
        p.digestType = old.digestType ?? ''
        p.newKeyTag = f.dsKeyTag
        p.newAlgorithm = f.dsAlgorithm
        p.newDigestType = f.dsDigestType
        p.digest = old.digest ?? ''
        p.newDigest = f.dsDigest
      }
      break
    }

    case 'SSHFP': {
      if (f.sshfpAlgorithm === '') {
        return missing(`Please select an Algorithm to ${verbo} the record.`, 'sshfpAlgorithm')
      }
      if (f.sshfpFingerprintType === '') {
        return missing(`Please select a Fingerprint Type to ${verbo} the record.`, 'sshfpFingerprintType')
      }
      if (f.sshfpFingerprint === '') {
        return missing(
          `Please enter the Fingerprint hash in hex string format to ${verbo} the record.`,
          'sshfpFingerprint',
        )
      }

      if (alta) {
        p.sshfpAlgorithm = f.sshfpAlgorithm
        p.sshfpFingerprintType = f.sshfpFingerprintType
        p.sshfpFingerprint = f.sshfpFingerprint
      } else {
        p.sshfpAlgorithm = old.sshfpAlgorithm ?? ''
        p.newSshfpAlgorithm = f.sshfpAlgorithm
        p.sshfpFingerprintType = old.sshfpFingerprintType ?? ''
        p.newSshfpFingerprintType = f.sshfpFingerprintType
        p.sshfpFingerprint = old.sshfpFingerprint ?? ''
        p.newSshfpFingerprint = f.sshfpFingerprint
      }
      break
    }

    case 'TLSA': {
      if (f.tlsaCertificateUsage === '') {
        return missing(`Please select a Certificate Usage to ${verbo} the record.`, 'tlsaCertificateUsage')
      }
      if (f.tlsaSelector === '') {
        return missing(`Please select a Selector to ${verbo} the record.`, 'tlsaSelector')
      }
      if (f.tlsaMatchingType === '') {
        return missing(`Please select a Matching Type to ${verbo} the record.`, 'tlsaMatchingType')
      }
      if (f.tlsaCertificateAssociationData === '') {
        return missing(
          `Please enter the Certificate Association Data to ${verbo} the record.`,
          'tlsaCertificateAssociationData',
        )
      }
      // Only on add: with "Full" it requires a complete PEM.
      if (
        alta &&
        f.tlsaMatchingType === 'Full' &&
        !f.tlsaCertificateAssociationData.startsWith('-')
      ) {
        return missing(
          'Please enter a complete certificate in PEM format as the Certificate Association Data to add the record.',
          'tlsaCertificateAssociationData',
        )
      }

      if (alta) {
        p.tlsaCertificateUsage = f.tlsaCertificateUsage
        p.tlsaSelector = f.tlsaSelector
        p.tlsaMatchingType = f.tlsaMatchingType
        p.tlsaCertificateAssociationData = f.tlsaCertificateAssociationData
      } else {
        p.tlsaCertificateUsage = old.tlsaCertificateUsage ?? ''
        p.newTlsaCertificateUsage = f.tlsaCertificateUsage
        p.tlsaSelector = old.tlsaSelector ?? ''
        p.newTlsaSelector = f.tlsaSelector
        p.tlsaMatchingType = old.tlsaMatchingType ?? ''
        p.newTlsaMatchingType = f.tlsaMatchingType
        p.tlsaCertificateAssociationData = old.tlsaCertificateAssociationData ?? ''
        p.newTlsaCertificateAssociationData = f.tlsaCertificateAssociationData
      }
      break
    }

    case 'SVCB':
    case 'HTTPS': {
      if (f.svcbPriority === '') {
        return missing(`Please enter a Priority value to ${verbo} the record.`, 'svcbPriority')
      }
      if (f.svcbTargetName === '') {
        return missing(`Please enter a Target Name to ${verbo} the record.`, 'svcbTargetName')
      }

      const params = serializeSvcParams(f.svcbParams)
      if ('error' in params) return params

      if (alta) {
        p.svcPriority = f.svcbPriority
        p.svcTargetName = f.svcbTargetName
        p.svcParams = params.value
      } else {
        p.svcPriority = old.svcPriority ?? ''
        p.newSvcPriority = f.svcbPriority
        p.svcTargetName = old.svcTargetName ?? ''
        p.newSvcTargetName = f.svcbTargetName
        p.svcParams = old.svcParams ?? 'false'
        p.newSvcParams = params.value
      }
      p.autoIpv4Hint = String(f.svcbAutoIpv4Hint)
      p.autoIpv6Hint = String(f.svcbAutoIpv6Hint)
      break
    }

    case 'URI': {
      if (f.uriPriority === '') return missing('Please enter a suitable priority.', 'uriPriority')
      if (f.uriWeight === '') return missing('Please enter a suitable weight.', 'uriWeight')
      if (f.uri === '') return missing('Please enter a suitable value into the URI field.', 'uri')

      if (alta) {
        p.uriPriority = f.uriPriority
        p.uriWeight = f.uriWeight
        p.uri = f.uri
      } else {
        p.uriPriority = old.uriPriority ?? ''
        p.newUriPriority = f.uriPriority
        p.uriWeight = old.uriWeight ?? ''
        p.newUriWeight = f.uriWeight
        p.uri = old.uri ?? ''
        p.newUri = f.uri
      }
      break
    }

    case 'CAA': {
      // The first two fall to default values, they do not error.
      const flags = f.caaFlags === '' ? '0' : f.caaFlags
      const tag = f.caaTag === '' ? 'issue' : f.caaTag
      if (f.caaValue === '') {
        return missing('Please enter a suitable value into the authority field.', 'caaValue')
      }

      if (alta) {
        p.flags = flags
        p.tag = tag
        p.value = f.caaValue
      } else {
        p.flags = old.flags ?? ''
        p.tag = old.tag ?? ''
        p.newFlags = flags
        p.newTag = tag
        p.value = old.value ?? ''
        p.newValue = f.caaValue
      }
      break
    }

    case 'ANAME': {
      if (f.value === '') return missing(`Please enter a suitable value to ${verbo} the record.`, 'value')
      if (alta) p.aname = f.value
      else {
        p.aname = old.aname ?? ''
        p.newAName = f.value
      }
      break
    }

    case 'FWD': {
      const reenviador = f.forwarder
      if (reenviador === '') {
        return missing(
          `Please enter a domain name or IP address or URL as a forwarder to ${verbo} the record.`,
          'forwarder',
        )
      }

      if (alta) {
        p.protocol = f.forwarderProtocol
        p.forwarder = reenviador
      } else {
        p.protocol = old.protocol ?? ''
        p.newProtocol = f.forwarderProtocol
        p.forwarder = old.forwarder ?? ''
        p.newForwarder = reenviador
      }
      p.forwarderPriority = f.forwarderPriority
      p.dnssecValidation = String(f.forwarderDnssecValidation)

      /*
      Here add and edit do NOT behave the same: when adding, the proxy is always
      sent; when editing, only if the new forwarder is not "this-server". It is
      asymmetric in upstream and it is replicated.
      */
      const mandarProxy = alta || reenviador !== 'this-server'
      if (mandarProxy) {
        p.proxyType = f.proxyType
        if (f.proxyType === 'Http' || f.proxyType === 'Socks5') {
          if (f.proxyAddress === '') {
            return missing(
              `Please enter a domain name or IP address for Proxy Server Address to ${verbo} the record.`,
              'proxyAddress',
            )
          }
          if (f.proxyPort === '') {
            return missing(
              `Please enter a port number for Proxy Server Port to ${verbo} the record.`,
              'proxyPort',
            )
          }
          p.proxyAddress = f.proxyAddress
          p.proxyPort = f.proxyPort
          p.proxyUsername = f.proxyUsername
          p.proxyPassword = f.proxyPassword
        }
      }
      break
    }

    case 'APP': {
      if (alta) {
        if (f.appName === '') {
          return missing('Please select an application name to add record.', 'appName')
        }
        if (f.classPath === '') {
          return missing('Please select a class path to add record.', 'classPath')
        }
        p.appName = f.appName
        p.classPath = f.classPath
        p.recordData = f.recordData
      } else {
        // On edit, the name and the class come from the record and are NOT validated.
        p.appName = old.appName ?? ''
        p.classPath = old.classPath ?? ''
        p.recordData = f.recordData
      }
      break
    }

    default: {
      // "Unknown": the type is typed by the user. Only the add requires it.
      type = f.unknownType
      if (alta && type === '') {
        return missing('Please enter a resoure record name or number to add record.', 'unknownType')
      }
      /*
      The two texts are NOT the same sentence with the verb swapped: the add
      says "to add record" and the edit "to update the record", with the article.
      And the "resoure" above is a typo of upstream's that is kept: they are
      contract, not prose of ours.
      */
      if (f.value === '') {
        return missing(
          alta
            ? 'Please enter a hex value as the RDATA to add record.'
            : 'Please enter a hex value as the RDATA to update the record.',
          'value',
        )
      }
      if (alta) p.rdata = f.value
      else {
        p.rdata = old.rdata ?? ''
        p.newRData = f.value
      }
      break
    }
  }

  const domain = dominioCompleto(ctx.zone, f.name)

  if (alta) {
    return {
      body: {
        zone: ctx.zone,
        domain,
        type,
        ttl: f.ttl,
        overwrite: String(f.overwrite),
        comments: f.comments,
        expiryTtl: f.expiryTtl,
        ...p,
      },
    }
  }

  const original = ctx.original
  return {
    body: {
      zone: ctx.zone,
      type,
      domain: original == null || original.name === '' ? '.' : original.name,
      newDomain: domain,
      ttl: f.ttl,
      // The edit does NOT change the state: it resends the one the record had.
      disable: String(original?.disabled === true),
      comments: f.comments,
      expiryTtl: f.expiryTtl,
      ...p,
    },
  }
}
