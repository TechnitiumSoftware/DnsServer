import { cleanList } from '../../../api/zonelists'

/*
The `modalAddZone` form and its validation (`addZone`, zone.js:2911).

It is kept apart from the component because it is the only thing in this modal
that can fail silently: which parameters travel depends on the chosen type, and
**each type sends a different set**. The whole `switch` is replicated here and it
tests on its own.

Two oddities of the original:

  · **"Secondary ROOT Zone" is not a type**: it is a Secondary with the thirteen
    root server addresses preloaded, `zoneTransferProtocol=Tcp` and
    `validateZone=true`. The type that travels is `Secondary`.

  · **The Catalog and Secondary Catalog types do not appear in the parameter
    `switch`**: they fall to the `default` and send none beyond zone and type…
    except SecondaryCatalog, which does have its branch next to
    SecondaryForwarder. Catalog, therefore, cannot register itself in another
    catalog on creation.
*/

export type AddZoneKind =
  | 'Primary'
  | 'Secondary'
  | 'Stub'
  | 'Forwarder'
  | 'SecondaryForwarder'
  | 'Catalog'
  | 'SecondaryCatalog'
  | 'SecondaryRoot'

export interface AddZoneOption {
  value: AddZoneKind
  label: string
  /** An external reference upstream draws in brackets after the label. */
  reference?: { text: string; href: string }
}

export const ADD_TYPES: AddZoneOption[] = [
  { value: 'Primary', label: 'Primary Zone (default)' },
  { value: 'Secondary', label: 'Secondary Zone' },
  { value: 'Stub', label: 'Stub Zone' },
  { value: 'Forwarder', label: 'Conditional Forwarder Zone' },
  { value: 'SecondaryForwarder', label: 'Secondary Conditional Forwarder Zone' },
  { value: 'Catalog', label: 'Catalog Zone' },
  { value: 'SecondaryCatalog', label: 'Secondary Catalog Zone' },
  {
    value: 'SecondaryRoot',
    label: 'Secondary ROOT Zone',
    // Upstream links the RFC from the type's own label.
    reference: { text: 'RFC 8806', href: 'https://datatracker.ietf.org/doc/rfc8806/' },
  },
]

/** The addresses of the thirteen root servers, copied literally from zone.js:3020. */
export const RAICES =
  '199.9.14.201,192.33.4.12,199.7.91.13,192.5.5.241,192.112.36.4,193.0.14.129,192.0.47.132,192.0.32.132,[2001:500:200::b],[2001:500:2::c],[2001:500:2d::d],[2001:500:2f::f],[2001:500:12::d0d],[2001:7fd::1],[2620:0:2830:202::132],[2620:0:2d0:202::132]'

export const TRANSFER_PROTOCOLS = [
  { value: 'Tcp', label: 'XFR-over-TCP (default)' },
  { value: 'Tls', label: 'XFR-over-TLS' },
  { value: 'Quic', label: 'XFR-over-QUIC' },
]

export const PROTOCOLOS_FORWARDER = [
  { value: 'Udp', label: 'DNS-over-UDP (default)' },
  { value: 'Tcp', label: 'DNS-over-TCP' },
  { value: 'Tls', label: 'DNS-over-TLS' },
  { value: 'Https', label: 'DNS-over-HTTPS' },
  { value: 'Quic', label: 'DNS-over-QUIC' },
]

export const PROXY_TYPES = [
  { value: 'NoProxy', label: 'No Proxy' },
  { value: 'DefaultProxy', label: 'Default Proxy (default)' },
  { value: 'Http', label: 'HTTP Proxy' },
  { value: 'Socks5', label: 'SOCKS5 Proxy' },
]

export interface FormularioAlta {
  zone: string
  type: AddZoneKind
  catalog: string
  useSoaSerialDateScheme: boolean
  primaryNameServerAddresses: string
  zoneTransferProtocol: string
  tsigKeyName: string
  validateZone: boolean
  initializeForwarder: boolean
  forwarderProtocol: string
  forwarder: string
  usarEsteServidor: boolean
  dnssecValidation: boolean
  proxyType: string
  proxyAddress: string
  proxyPort: string
  proxyUsername: string
  proxyPassword: string
}

export function formularioAltaInicial(useSoaSerialDateScheme: boolean, dnssecValidation: boolean): FormularioAlta {
  return {
    zone: '',
    type: 'Primary',
    catalog: '',
    // Both inherit from the global setting on the Settings screen, not from false.
    useSoaSerialDateScheme,
    primaryNameServerAddresses: '',
    zoneTransferProtocol: 'Tcp',
    tsigKeyName: '',
    validateZone: false,
    initializeForwarder: true,
    forwarderProtocol: 'Udp',
    forwarder: '',
    usarEsteServidor: false,
    dnssecValidation,
    proxyType: 'DefaultProxy',
    proxyAddress: '',
    proxyPort: '',
    proxyUsername: '',
    proxyPassword: '',
  }
}

export interface AddError {
  title: string
  text: string
  /** Which field receives the focus, just as upstream does. */
  field: keyof FormularioAlta
}

export type ResultadoAlta = { error: AddError } | { params: Record<string, string> }

export interface SeccionesAlta {
  /** Only if the dropdown also brought catalogs (`hasItems`). */
  catalogo: boolean
  zoneFile: boolean
  serieSoa: boolean
  servidoresPrimarios: boolean
  /** The label and the help change: optional for Secondary and Stub, required
   *  for the two forwarder and catalog secondaries. */
  servidoresPrimariosObligatorios: boolean
  transferProtocol: boolean
  tsig: boolean
  validateZone: boolean
  casillaInicializarForwarder: boolean
  forwarderFields: boolean
  /** "Secondary ROOT" pins the zone to "." and locks the field. */
  fixedZone: string | null
}

/**
 * Which sections of the form show, by type. A literal replica of the
 * `rdAddZoneType` handler (zone.js:26-118), including that **Catalog shows
 * NOTHING**: it has no branch in the `switch`, so only the name and the type
 * remain.
 */
export function seccionesVisibles(type: AddZoneKind, initializeForwarder: boolean): SeccionesAlta {
  const base: SeccionesAlta = {
    catalogo: false,
    zoneFile: false,
    serieSoa: false,
    servidoresPrimarios: false,
    servidoresPrimariosObligatorios: false,
    transferProtocol: false,
    tsig: false,
    validateZone: false,
    casillaInicializarForwarder: false,
    forwarderFields: false,
    fixedZone: null,
  }

  switch (type) {
    case 'Primary':
      return { ...base, catalogo: true, zoneFile: true, serieSoa: true }

    case 'Secondary':
      return {
        ...base,
        catalogo: true,
        servidoresPrimarios: true,
        transferProtocol: true,
        tsig: true,
        validateZone: true,
      }

    case 'Stub':
      return { ...base, catalogo: true, servidoresPrimarios: true }

    case 'Forwarder':
      // The zone file and the forwarder fields are mutually exclusive.
      return {
        ...base,
        catalogo: true,
        casillaInicializarForwarder: true,
        zoneFile: !initializeForwarder,
        forwarderFields: initializeForwarder,
      }

    case 'SecondaryForwarder':
    case 'SecondaryCatalog':
      return {
        ...base,
        servidoresPrimarios: true,
        servidoresPrimariosObligatorios: true,
        transferProtocol: true,
        tsig: true,
      }

    case 'SecondaryRoot':
      return { ...base, catalogo: true, fixedZone: '.' }

    default:
      return base
  }
}

/** The "Forwarder" field's example changes with the protocol (zone.js:139-152). */
export function ejemploDeForwarder(protocolo: string): string {
  switch (protocolo) {
    case 'Tls':
    case 'Quic':
      return 'dns.quad9.net (9.9.9.9:853)'
    case 'Https':
      return 'https://cloudflare-dns.com/dns-query (1.1.1.1)'
    default:
      return '8.8.8.8 or [2620:fe::10]'
  }
}

/** The proxy fields go off with "No Proxy" and "Default Proxy". */
export function proxyEditable(proxyType: string): boolean {
  return proxyType !== 'NoProxy' && proxyType !== 'DefaultProxy'
}

export function buildAddParams(f: FormularioAlta): ResultadoAlta {
  if (f.zone === '') {
    return {
      error: { title: 'Missing!', text: 'Please enter a domain name to add zone.', field: 'zone' },
    }
  }

  let type: string = f.type
  const p: Record<string, string> = {}

  switch (f.type) {
    case 'Primary':
      p.catalog = f.catalog
      p.useSoaSerialDateScheme = String(f.useSoaSerialDateScheme)
      break

    case 'Secondary':
      p.catalog = f.catalog
      p.primaryNameServerAddresses = cleanList(f.primaryNameServerAddresses)
      p.zoneTransferProtocol = f.zoneTransferProtocol
      p.tsigKeyName = f.tsigKeyName
      p.validateZone = String(f.validateZone)
      break

    case 'Stub':
      p.catalog = f.catalog
      p.primaryNameServerAddresses = cleanList(f.primaryNameServerAddresses)
      break

    case 'Forwarder': {
      if (!f.initializeForwarder) {
        p.initializeForwarder = 'false'
        break
      }

      const forwarder = f.usarEsteServidor ? 'this-server' : f.forwarder
      if (forwarder === '') {
        return {
          error: {
            title: 'Missing!',
            text: 'Please enter a forwarder server address to add zone.',
            field: 'forwarder',
          },
        }
      }

      p.catalog = f.catalog
      p.protocol = f.usarEsteServidor ? 'Udp' : f.forwarderProtocol
      p.forwarder = forwarder
      p.dnssecValidation = String(f.dnssecValidation)

      // "this-server" takes no proxy: upstream does not even send `proxyType`.
      if (forwarder !== 'this-server') {
        p.proxyType = f.proxyType

        if (f.proxyType === 'Http' || f.proxyType === 'Socks5') {
          if (f.proxyAddress === '') {
            return {
              error: {
                title: 'Missing!',
                text: 'Please enter a domain name or IP address for Proxy Server Address to add zone.',
                field: 'proxyAddress',
              },
            }
          }
          if (f.proxyPort === '') {
            return {
              error: {
                title: 'Missing!',
                text: 'Please enter a port number for Proxy Server Port to add zone.',
                field: 'proxyPort',
              },
            }
          }
          p.proxyAddress = f.proxyAddress
          p.proxyPort = f.proxyPort
          p.proxyUsername = f.proxyUsername
          p.proxyPassword = f.proxyPassword
        }
      }

      p.initializeForwarder = 'true'
      break
    }

    case 'SecondaryForwarder':
    case 'SecondaryCatalog': {
      const addresses = cleanList(f.primaryNameServerAddresses)
      if (addresses.length === 0 || addresses === ',') {
        return {
          error: {
            title: 'Missing!',
            text: 'Please enter at least one primary name server address to proceed.',
            field: 'primaryNameServerAddresses',
          },
        }
      }
      p.primaryNameServerAddresses = addresses
      p.zoneTransferProtocol = f.zoneTransferProtocol
      p.tsigKeyName = f.tsigKeyName
      break
    }

    case 'SecondaryRoot':
      type = 'Secondary'
      p.catalog = f.catalog
      p.primaryNameServerAddresses = RAICES
      p.zoneTransferProtocol = 'Tcp'
      p.validateZone = 'true'
      break

    default:
      break
  }

  return { params: { zone: f.zone, type, ...p } }
}

/** Only Primary and Forwarder accept a zone file on creation (zone.js:3030). */
export function acceptsZoneFile(type: AddZoneKind): boolean {
  return type === 'Primary' || type === 'Forwarder'
}
