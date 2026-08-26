import { limpiarLista } from '../../../api/zonelists'

/*
El formulario de `modalAddZone` y su validación (`addZone`, zone.js:2911).

Se separa del componente porque es lo único de este modal que puede fallar en
silencio: qué parámetros viajan depende del tipo elegido, y **cada tipo manda un
conjunto distinto**. Aquí se replica el `switch` entero y se prueba solo.

Dos rarezas del original:

  · **«Secondary ROOT Zone» no es un tipo**: es una Secondary con las trece
    direcciones de los servidores raíz precargadas, `zoneTransferProtocol=Tcp`
    y `validateZone=true`. El tipo que viaja es `Secondary`.

  · **Los tipos Catalog y Secondary Catalog no aparecen en el `switch`** de
    parámetros: caen al `default` y no mandan ninguno más allá de zona y tipo…
    salvo SecondaryCatalog, que sí tiene su rama junto a SecondaryForwarder.
    Catalog, por tanto, no puede registrarse en otro catálogo al crearse.
*/

export type TipoAlta =
  | 'Primary'
  | 'Secondary'
  | 'Stub'
  | 'Forwarder'
  | 'SecondaryForwarder'
  | 'Catalog'
  | 'SecondaryCatalog'
  | 'SecondaryRoot'

export const TIPOS_ALTA: { valor: TipoAlta; etiqueta: string }[] = [
  { valor: 'Primary', etiqueta: 'Primary Zone (default)' },
  { valor: 'Secondary', etiqueta: 'Secondary Zone' },
  { valor: 'Stub', etiqueta: 'Stub Zone' },
  { valor: 'Forwarder', etiqueta: 'Conditional Forwarder Zone' },
  { valor: 'SecondaryForwarder', etiqueta: 'Secondary Conditional Forwarder Zone' },
  { valor: 'Catalog', etiqueta: 'Catalog Zone' },
  { valor: 'SecondaryCatalog', etiqueta: 'Secondary Catalog Zone' },
  { valor: 'SecondaryRoot', etiqueta: 'Secondary ROOT Zone (RFC 8806)' },
]

/** Las direcciones de los trece servidores raíz, copiadas literales de zone.js:3020. */
export const RAICES =
  '199.9.14.201,192.33.4.12,199.7.91.13,192.5.5.241,192.112.36.4,193.0.14.129,192.0.47.132,192.0.32.132,[2001:500:200::b],[2001:500:2::c],[2001:500:2d::d],[2001:500:2f::f],[2001:500:12::d0d],[2001:7fd::1],[2620:0:2830:202::132],[2620:0:2d0:202::132]'

export const PROTOCOLOS_TRANSFERENCIA = [
  { valor: 'Tcp', etiqueta: 'XFR-over-TCP (default)' },
  { valor: 'Tls', etiqueta: 'XFR-over-TLS' },
  { valor: 'Quic', etiqueta: 'XFR-over-QUIC' },
]

export const PROTOCOLOS_FORWARDER = [
  { valor: 'Udp', etiqueta: 'DNS-over-UDP (default)' },
  { valor: 'Tcp', etiqueta: 'DNS-over-TCP' },
  { valor: 'Tls', etiqueta: 'DNS-over-TLS' },
  { valor: 'Https', etiqueta: 'DNS-over-HTTPS' },
  { valor: 'Quic', etiqueta: 'DNS-over-QUIC' },
]

export const TIPOS_PROXY = [
  { valor: 'NoProxy', etiqueta: 'No Proxy' },
  { valor: 'DefaultProxy', etiqueta: 'Default Proxy (default)' },
  { valor: 'Http', etiqueta: 'HTTP Proxy' },
  { valor: 'Socks5', etiqueta: 'SOCKS5 Proxy' },
]

export interface FormularioAlta {
  zone: string
  tipo: TipoAlta
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
    tipo: 'Primary',
    catalog: '',
    // Los dos heredan del ajuste global de la pantalla de Settings, no de false.
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

export interface ErrorAlta {
  title: string
  text: string
  /** Qué campo recibe el foco, igual que hace upstream. */
  campo: keyof FormularioAlta
}

export type ResultadoAlta = { error: ErrorAlta } | { parametros: Record<string, string> }

export interface SeccionesAlta {
  /** Sólo si además el desplegable trajo catálogos (`hasItems`). */
  catalogo: boolean
  ficheroDeZona: boolean
  serieSoa: boolean
  servidoresPrimarios: boolean
  /** El rótulo y la ayuda cambian: opcional para Secondary y Stub, obligatorio
   *  para las dos secundarias de reenvío y catálogo. */
  servidoresPrimariosObligatorios: boolean
  protocoloTransferencia: boolean
  tsig: boolean
  validarZona: boolean
  casillaInicializarForwarder: boolean
  camposDeForwarder: boolean
  /** «Secondary ROOT» fija la zona a «.» y bloquea el campo. */
  zonaFija: string | null
}

/**
 * Qué secciones del formulario se ven, por tipo. Réplica literal del
 * manejador de `rdAddZoneType` (zone.js:26-118), incluido que **Catalog no
 * enseña NADA**: no tiene rama en el `switch`, así que sólo quedan el nombre y
 * el tipo.
 */
export function seccionesVisibles(tipo: TipoAlta, initializeForwarder: boolean): SeccionesAlta {
  const base: SeccionesAlta = {
    catalogo: false,
    ficheroDeZona: false,
    serieSoa: false,
    servidoresPrimarios: false,
    servidoresPrimariosObligatorios: false,
    protocoloTransferencia: false,
    tsig: false,
    validarZona: false,
    casillaInicializarForwarder: false,
    camposDeForwarder: false,
    zonaFija: null,
  }

  switch (tipo) {
    case 'Primary':
      return { ...base, catalogo: true, ficheroDeZona: true, serieSoa: true }

    case 'Secondary':
      return {
        ...base,
        catalogo: true,
        servidoresPrimarios: true,
        protocoloTransferencia: true,
        tsig: true,
        validarZona: true,
      }

    case 'Stub':
      return { ...base, catalogo: true, servidoresPrimarios: true }

    case 'Forwarder':
      // El fichero de zona y los campos del reenviador se excluyen entre sí.
      return {
        ...base,
        catalogo: true,
        casillaInicializarForwarder: true,
        ficheroDeZona: !initializeForwarder,
        camposDeForwarder: initializeForwarder,
      }

    case 'SecondaryForwarder':
    case 'SecondaryCatalog':
      return {
        ...base,
        servidoresPrimarios: true,
        servidoresPrimariosObligatorios: true,
        protocoloTransferencia: true,
        tsig: true,
      }

    case 'SecondaryRoot':
      return { ...base, catalogo: true, zonaFija: '.' }

    default:
      return base
  }
}

/** El ejemplo del campo «Forwarder» cambia con el protocolo (zone.js:139-152). */
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

/** Los campos del proxy se apagan con «No Proxy» y «Default Proxy». */
export function proxyEditable(proxyType: string): boolean {
  return proxyType !== 'NoProxy' && proxyType !== 'DefaultProxy'
}

export function construirParametrosAlta(f: FormularioAlta): ResultadoAlta {
  if (f.zone === '') {
    return {
      error: { title: 'Missing!', text: 'Please enter a domain name to add zone.', campo: 'zone' },
    }
  }

  let type: string = f.tipo
  const p: Record<string, string> = {}

  switch (f.tipo) {
    case 'Primary':
      p.catalog = f.catalog
      p.useSoaSerialDateScheme = String(f.useSoaSerialDateScheme)
      break

    case 'Secondary':
      p.catalog = f.catalog
      p.primaryNameServerAddresses = limpiarLista(f.primaryNameServerAddresses)
      p.zoneTransferProtocol = f.zoneTransferProtocol
      p.tsigKeyName = f.tsigKeyName
      p.validateZone = String(f.validateZone)
      break

    case 'Stub':
      p.catalog = f.catalog
      p.primaryNameServerAddresses = limpiarLista(f.primaryNameServerAddresses)
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
            campo: 'forwarder',
          },
        }
      }

      p.catalog = f.catalog
      p.protocol = f.usarEsteServidor ? 'Udp' : f.forwarderProtocol
      p.forwarder = forwarder
      p.dnssecValidation = String(f.dnssecValidation)

      // «this-server» no admite proxy: upstream ni siquiera manda `proxyType`.
      if (forwarder !== 'this-server') {
        p.proxyType = f.proxyType

        if (f.proxyType === 'Http' || f.proxyType === 'Socks5') {
          if (f.proxyAddress === '') {
            return {
              error: {
                title: 'Missing!',
                text: 'Please enter a domain name or IP address for Proxy Server Address to add zone.',
                campo: 'proxyAddress',
              },
            }
          }
          if (f.proxyPort === '') {
            return {
              error: {
                title: 'Missing!',
                text: 'Please enter a port number for Proxy Server Port to add zone.',
                campo: 'proxyPort',
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
      const direcciones = limpiarLista(f.primaryNameServerAddresses)
      if (direcciones.length === 0 || direcciones === ',') {
        return {
          error: {
            title: 'Missing!',
            text: 'Please enter at least one primary name server address to proceed.',
            campo: 'primaryNameServerAddresses',
          },
        }
      }
      p.primaryNameServerAddresses = direcciones
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

  return { parametros: { zone: f.zone, type, ...p } }
}

/** Sólo Primary y Forwarder aceptan un fichero de zona al crear (zone.js:3030). */
export function admiteFicheroDeZona(tipo: TipoAlta): boolean {
  return tipo === 'Primary' || tipo === 'Forwarder'
}
