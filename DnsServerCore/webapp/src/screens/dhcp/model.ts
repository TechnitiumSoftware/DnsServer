import type { DhcpScope } from '../../api/dhcp'

/*
El formulario de un scope DHCP: 36 campos, cinco de ellos tablas editables.

Todo lo que valida upstream antes de guardar está en `serializeTableData`
(common.js:282-324). No hay ninguna otra comprobación en el cliente: el resto lo
rechaza el servidor. Aquí se replica esa función tal cual, incluidos:

  · el ORDEN — celda a celda, fila a fila, y las cinco tablas en el orden en que
    `saveDhcpScope` las serializa: rutas estáticas, información de fabricante,
    opciones genéricas, exclusiones y reservas (dhcp.js:525-547). Las dos listas
    de texto que se leen entre medias (CAPWAP y TFTP) no validan nada;
  · los DOS avisos, con sus textos literales y en su orden: primero «vacío»,
    después «carácter prohibido»;
  · qué celdas son OPCIONALES (`data-optional="true"`): el identificador de
    fabricante, y el nombre de host y los comentarios de una reserva. Ninguna
    otra puede quedarse vacía.

Un detalle de upstream que aquí NO se replica, y a propósito: `serializeTableData`
aplica `htmlDecode` al valor que acaba de leer del DOM, donde el navegador YA lo
había decodificado al parsear el HTML. Es una segunda decodificación sobre un
texto ya limpio: escribir `&amp;` en una celda lo manda al servidor como `&`. En
React no hay HTML intermedio, así que el valor viaja tal cual se escribió.
Replicar la doble decodificación sería introducir el fallo a mano.
*/

export interface FilaRutaEstatica {
  destination: string
  subnetMask: string
  router: string
}
export interface FilaVendorInfo {
  identifier: string
  information: string
}
export interface FilaOpcionGenerica {
  code: string
  value: string
}
export interface FilaExclusion {
  startingAddress: string
  endingAddress: string
}
export interface FilaReserva {
  hostName: string
  hardwareAddress: string
  address: string
  comments: string
}

export interface ScopeForm {
  /** El `data-name` del campo Name: el nombre con el que se cargó el scope.
   *  Vacío en un scope nuevo. Es lo que decide si hay renombrado. */
  oldName: string
  name: string
  startingAddress: string
  endingAddress: string
  subnetMask: string
  leaseTimeDays: string
  leaseTimeHours: string
  leaseTimeMinutes: string
  offerDelayTime: string
  pingCheckEnabled: boolean
  pingCheckTimeout: string
  pingCheckRetries: string
  domainName: string
  domainSearchList: string
  dnsUpdates: boolean
  dnsOverwriteForDynamicLease: boolean
  dnsTtl: string
  serverAddress: string
  serverHostName: string
  bootFileName: string
  routerAddress: string
  useThisDnsServer: boolean
  dnsServers: string
  winsServers: string
  ntpServers: string
  ntpServerDomainNames: string
  staticRoutes: FilaRutaEstatica[]
  vendorInfo: FilaVendorInfo[]
  capwapAcIpAddresses: string
  tftpServerAddresses: string
  genericOptions: FilaOpcionGenerica[]
  exclusions: FilaExclusion[]
  reservedLeases: FilaReserva[]
  allowOnlyReservedLeases: boolean
  blockLocallyAdministeredMacAddresses: boolean
  ignoreClientIdentifierOption: boolean
}

/** `clearDhcpScopeForm` (dhcp.js:310). Los valores por defecto son de upstream,
 *  no elecciones nuestras: 1 día de concesión, ping check a 1000 ms y 2
 *  reintentos, TTL de DNS 900 s, actualizaciones de DNS marcadas e identificador
 *  de cliente ignorado. */
export function formularioVacio(): ScopeForm {
  return {
    oldName: '',
    name: '',
    startingAddress: '',
    endingAddress: '',
    subnetMask: '',
    leaseTimeDays: '1',
    leaseTimeHours: '0',
    leaseTimeMinutes: '0',
    offerDelayTime: '0',
    pingCheckEnabled: false,
    pingCheckTimeout: '1000',
    pingCheckRetries: '2',
    domainName: '',
    domainSearchList: '',
    dnsUpdates: true,
    dnsOverwriteForDynamicLease: false,
    dnsTtl: '900',
    serverAddress: '',
    serverHostName: '',
    bootFileName: '',
    routerAddress: '',
    useThisDnsServer: false,
    dnsServers: '',
    winsServers: '',
    ntpServers: '',
    ntpServerDomainNames: '',
    staticRoutes: [],
    vendorInfo: [],
    capwapAcIpAddresses: '',
    tftpServerAddresses: '',
    genericOptions: [],
    exclusions: [],
    reservedLeases: [],
    allowOnlyReservedLeases: false,
    blockLocallyAdministeredMacAddresses: false,
    ignoreClientIdentifierOption: true,
  }
}

/** `showAddDhcpScope` (dhcp.js:352) parte del formulario vacío pero marca
 *  «Use This DNS Server», que a su vez deshabilita el área de servidores DNS. */
export function formularioNuevo(): ScopeForm {
  return { ...formularioVacio(), useThisDnsServer: true }
}

/** Un array de cadenas a textarea, con salto de línea entre elementos
 *  (`.join("\n")`, dhcp.js:399 y siguientes). */
export function listaATexto(lista: string[] | undefined): string {
  return lista == null ? '' : lista.join('\n')
}

/** `cleanTextList` (common.js:326): saltos de línea a comas, comas repetidas
 *  colapsadas y sin comas en los extremos. */
export function limpiarLista(texto: string): string {
  let t = texto.replace(/\n/g, ',')
  while (t.includes(',,')) t = t.replace(/,,/g, ',')
  if (t.startsWith(',')) t = t.substring(1)
  if (t.endsWith(',')) t = t.substring(0, t.length - 1)
  return t
}

/** `showEditDhcpScope` (dhcp.js:363). Los campos que el servidor OMITE cuando
 *  son nulos se quedan como estaban en el formulario vacío. */
export function formularioDesdeScope(s: DhcpScope): ScopeForm {
  const f = formularioVacio()
  return {
    ...f,
    oldName: s.name,
    name: s.name,
    startingAddress: s.startingAddress,
    endingAddress: s.endingAddress,
    subnetMask: s.subnetMask,
    leaseTimeDays: String(s.leaseTimeDays),
    leaseTimeHours: String(s.leaseTimeHours),
    leaseTimeMinutes: String(s.leaseTimeMinutes),
    offerDelayTime: String(s.offerDelayTime),
    pingCheckEnabled: s.pingCheckEnabled,
    pingCheckTimeout: String(s.pingCheckTimeout),
    pingCheckRetries: String(s.pingCheckRetries),
    domainName: s.domainName ?? '',
    domainSearchList: listaATexto(s.domainSearchList),
    dnsUpdates: s.dnsUpdates,
    dnsOverwriteForDynamicLease: s.dnsOverwriteForDynamicLease,
    dnsTtl: String(s.dnsTtl),
    serverAddress: s.serverAddress ?? '',
    serverHostName: s.serverHostName ?? '',
    bootFileName: s.bootFileName ?? '',
    routerAddress: s.routerAddress ?? '',
    useThisDnsServer: s.useThisDnsServer,
    dnsServers: listaATexto(s.dnsServers),
    winsServers: listaATexto(s.winsServers),
    ntpServers: listaATexto(s.ntpServers),
    ntpServerDomainNames: listaATexto(s.ntpServerDomainNames),
    staticRoutes: (s.staticRoutes ?? []).map((r) => ({
      destination: r.destination,
      subnetMask: r.subnetMask,
      router: r.router,
    })),
    vendorInfo: (s.vendorInfo ?? []).map((v) => ({
      identifier: v.identifier,
      information: v.information,
    })),
    capwapAcIpAddresses: listaATexto(s.capwapAcIpAddresses),
    tftpServerAddresses: listaATexto(s.tftpServerAddresses),
    genericOptions: (s.genericOptions ?? []).map((o) => ({
      code: String(o.code),
      value: o.value,
    })),
    exclusions: (s.exclusions ?? []).map((e) => ({
      startingAddress: e.startingAddress,
      endingAddress: e.endingAddress,
    })),
    reservedLeases: (s.reservedLeases ?? []).map((r) => ({
      hostName: r.hostName ?? '',
      hardwareAddress: r.hardwareAddress,
      address: r.address,
      comments: r.comments ?? '',
    })),
    allowOnlyReservedLeases: s.allowOnlyReservedLeases,
    blockLocallyAdministeredMacAddresses: s.blockLocallyAdministeredMacAddresses,
    ignoreClientIdentifierOption: s.ignoreClientIdentifierOption,
  }
}

export interface ErrorScope {
  title: string
  text: string
  /** `id` del control que upstream enfoca. El texto del aviso habla del «campo
   *  con el foco», así que sin esto el aviso no se puede resolver. */
  focus: string
}

/** El `id` de una celda de tabla. Determinista para poder enfocarla. */
export function idCelda(tabla: string, fila: number, columna: string): string {
  return `dhcp-${tabla}-${fila}-${columna}`
}

/*
`serializeTableData` (common.js:282). Devuelve las celdas de todas las filas
unidas por `|`, o el aviso de la primera celda que no vale.
*/
function serializar(
  tabla: string,
  filas: Record<string, string>[],
  columnas: { key: string; optional?: boolean }[],
): { valor: string } | { error: ErrorScope } {
  const partes: string[] = []

  for (let i = 0; i < filas.length; i++) {
    for (const col of columnas) {
      const valor = filas[i][col.key] ?? ''

      if (valor === '' && col.optional !== true) {
        return {
          error: {
            title: 'Missing!',
            text: 'Please enter a valid value in the text field in focus.',
            focus: idCelda(tabla, i, col.key),
          },
        }
      }

      if (valor.includes('|')) {
        return {
          error: {
            title: 'Invalid Character!',
            text: "Please edit the value in the text field in focus to remove '|' character.",
            focus: idCelda(tabla, i, col.key),
          },
        }
      }

      partes.push(valor)
    }
  }

  return { valor: partes.join('|') }
}

/*
`saveDhcpScope` (dhcp.js:485). Arma el cuerpo del POST en el mismo orden y con
las mismas reglas:

  · si el scope ya existía y el nombre cambió, `name` lleva el VIEJO y aparece
    `newName` con el nuevo;
  · `dnsServers` no se manda si «Use This DNS Server» está marcado;
  · las cinco tablas se validan en el orden en que se serializan, y el primer
    fallo aborta el guardado.
*/
export function construirCuerpo(
  f: ScopeForm,
): { body: Record<string, string> } | { error: ErrorScope } {
  let name = f.name
  let newName: string | null = null

  if (f.oldName !== '' && f.oldName !== name) {
    newName = name
    name = f.oldName
  }

  const staticRoutes = serializar('staticRoutes', f.staticRoutes as unknown as Record<string, string>[], [
    { key: 'destination' },
    { key: 'subnetMask' },
    { key: 'router' },
  ])
  if ('error' in staticRoutes) return staticRoutes

  const vendorInfo = serializar('vendorInfo', f.vendorInfo as unknown as Record<string, string>[], [
    { key: 'identifier', optional: true },
    { key: 'information' },
  ])
  if ('error' in vendorInfo) return vendorInfo

  const genericOptions = serializar(
    'genericOptions',
    f.genericOptions as unknown as Record<string, string>[],
    [{ key: 'code' }, { key: 'value' }],
  )
  if ('error' in genericOptions) return genericOptions

  const exclusions = serializar('exclusions', f.exclusions as unknown as Record<string, string>[], [
    { key: 'startingAddress' },
    { key: 'endingAddress' },
  ])
  if ('error' in exclusions) return exclusions

  const reservedLeases = serializar(
    'reservedLeases',
    f.reservedLeases as unknown as Record<string, string>[],
    [
      { key: 'hostName', optional: true },
      { key: 'hardwareAddress' },
      { key: 'address' },
      { key: 'comments', optional: true },
    ],
  )
  if ('error' in reservedLeases) return reservedLeases

  const body: Record<string, string> = { name }
  if (newName !== null) body.newName = newName

  body.startingAddress = f.startingAddress
  body.endingAddress = f.endingAddress
  body.subnetMask = f.subnetMask
  body.leaseTimeDays = f.leaseTimeDays
  body.leaseTimeHours = f.leaseTimeHours
  body.leaseTimeMinutes = f.leaseTimeMinutes
  body.offerDelayTime = f.offerDelayTime
  body.pingCheckEnabled = String(f.pingCheckEnabled)
  body.pingCheckTimeout = f.pingCheckTimeout
  body.pingCheckRetries = f.pingCheckRetries
  body.domainName = f.domainName
  body.domainSearchList = limpiarLista(f.domainSearchList)
  body.dnsUpdates = String(f.dnsUpdates)
  body.dnsOverwriteForDynamicLease = String(f.dnsOverwriteForDynamicLease)
  body.dnsTtl = f.dnsTtl
  body.serverAddress = f.serverAddress
  body.serverHostName = f.serverHostName
  body.bootFileName = f.bootFileName
  body.routerAddress = f.routerAddress
  body.useThisDnsServer = String(f.useThisDnsServer)
  if (!f.useThisDnsServer) body.dnsServers = limpiarLista(f.dnsServers)
  body.winsServers = limpiarLista(f.winsServers)
  body.ntpServers = limpiarLista(f.ntpServers)
  body.ntpServerDomainNames = limpiarLista(f.ntpServerDomainNames)
  body.staticRoutes = staticRoutes.valor
  body.vendorInfo = vendorInfo.valor
  body.capwapAcIpAddresses = limpiarLista(f.capwapAcIpAddresses)
  body.tftpServerAddresses = limpiarLista(f.tftpServerAddresses)
  body.genericOptions = genericOptions.valor
  body.exclusions = exclusions.valor
  body.reservedLeases = reservedLeases.valor
  body.allowOnlyReservedLeases = String(f.allowOnlyReservedLeases)
  body.blockLocallyAdministeredMacAddresses = String(f.blockLocallyAdministeredMacAddresses)
  body.ignoreClientIdentifierOption = String(f.ignoreClientIdentifierOption)

  return { body }
}
