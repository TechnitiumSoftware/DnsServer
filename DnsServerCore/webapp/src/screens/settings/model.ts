import type { DnsSettings } from '../../api/settings'

/*
El modelo del formulario de Settings.

La consola antigua no tiene modelo: lee y escribe el DOM. Aquí se replica ese
DOM campo a campo —cada `<input>` es una cadena, cada `<textarea>` una cadena con
saltos de línea, cada `<table>` una lista de filas— para que el orden de
validación y el cuerpo que se manda salgan IDÉNTICOS a `saveDnsSettings`
(main.js:1631-2236).

Dos convenciones de upstream que hay que respetar al pie de la letra:

  · Una lista vacía se manda como la CADENA `"false"`, no se omite. Sale de
    concatenar `x = false` a la query. El servidor lo interpreta como «vacía».
    Dos excepciones: los End Points y las direcciones locales del Web Service,
    que se rellenan con su valor por defecto, y `proxyBypass`, que se manda
    como cadena vacía.
  · Tras guardar, upstream REESCRIBE el textarea con la lista saneada. Unas
    veces con salto de línea al final y otras no; esa asimetría se copia tal
    cual para no cambiar lo que ve el usuario.
*/

export interface QpmRow { prefix: string; udpLimit: string; tcpLimit: string }
export interface TsigRow { keyName: string; sharedSecret: string; algorithmName: string }

export interface SettingsForm {
  // General — parámetros locales
  dnsServerDomain: string
  dnsServerLocalEndPoints: string
  dnsServerIPv4SourceAddresses: string
  dnsServerIPv6SourceAddresses: string

  // General — valores por defecto
  defaultRecordTtl: string
  defaultNsRecordTtl: string
  defaultSoaRecordTtl: string
  defaultResponsiblePerson: string
  useSoaSerialDateScheme: boolean
  minSoaRefresh: string
  minSoaRetry: string
  zoneTransferAllowedNetworks: string
  notifyAllowedNetworks: string

  // General — actualización
  dnsServerEnableCheckForUpdate: boolean
  dnsAppsEnableAutomaticUpdate: boolean

  // General — IPv6 y socket pool
  ipv6Mode: string
  enableUdpSocketPool: boolean
  socketPoolExcludedPorts: string

  // General — EDNS / DNSSEC / ECS
  udpPayloadSize: string
  dnssecValidation: boolean
  eDnsClientSubnet: boolean
  eDnsClientSubnetIPv4PrefixLength: string
  eDnsClientSubnetIPv6PrefixLength: string
  eDnsClientSubnetIpv4Override: string
  eDnsClientSubnetIpv6Override: string

  // General — QPM
  qpmPrefixLimitsIPv4: QpmRow[]
  qpmPrefixLimitsIPv6: QpmRow[]
  qpmLimitSampleMinutes: string
  qpmLimitUdpTruncationPercentage: string
  qpmLimitBypassList: string

  // General — avanzado
  clientTimeout: string
  tcpSendTimeout: string
  tcpReceiveTimeout: string
  quicIdleTimeout: string
  quicMaxInboundStreams: string
  listenBacklog: string
  udpSendBufferSizeKB: string
  udpReceiveBufferSizeKB: string
  maxConcurrentResolutionsPerCore: string

  // Web Service
  webServiceLocalAddresses: string
  webServiceHttpPort: string
  webServiceEnableHttpUnixSocket: boolean
  webServiceHttpUnixSocket: string
  webServiceEnableTlsUnixSocket: boolean
  webServiceTlsUnixSocket: string
  webServiceEnableTls: boolean
  webServiceEnableHttp3: boolean
  webServiceHttpToTlsRedirect: boolean
  webServiceUseSelfSignedTlsCertificate: boolean
  webServiceTlsPort: string
  webServiceReverseProxyAddresses: string
  webServiceRealIpHeader: string
  webServiceCspFrameAncestorsHeader: string
  webServiceTlsCertificatePath: string
  webServiceTlsCertificatePassword: string

  // Optional Protocols
  enableEDnsClientSubnetSourceAddress: boolean
  enableDnsOverUdpProxy: boolean
  enableDnsOverTcpProxy: boolean
  enableDnsOverHttp: boolean
  enableDnsOverHttpUnixSocket: boolean
  enableDnsOverHttpsUnixSocket: boolean
  enableDnsOverTls: boolean
  enableDnsOverHttps: boolean
  enableDnsOverHttp3: boolean
  enableDnsOverQuic: boolean
  enableDnsOverHttpHelpRedirect: boolean
  dnsOverUdpProxyPort: string
  dnsOverTcpProxyPort: string
  dnsOverHttpPort: string
  dnsOverHttpUnixSocket: string
  dnsOverHttpsUnixSocket: string
  dnsOverTlsPort: string
  dnsOverHttpsPort: string
  dnsOverQuicPort: string
  dnsReverseProxyNetworkACL: string
  dnsOverHttpRealIpHeader: string
  dnsTlsCertificatePath: string
  dnsTlsCertificatePassword: string

  // TSIG
  tsigKeys: TsigRow[]

  // Recursion
  recursion: string
  recursionNetworkACL: string
  randomizeName: boolean
  qnameMinimization: boolean
  locallyServedDnsZones: boolean
  resolverRetries: string
  resolverTimeout: string
  resolverConcurrency: string
  resolverMaxStackCount: string

  // Cache
  saveCache: boolean
  serveStale: boolean
  serveStaleTtl: string
  serveStaleAnswerTtl: string
  serveStaleResetTtl: string
  serveStaleMaxWaitTime: string
  cacheMaximumEntries: string
  cacheMinimumRecordTtl: string
  cacheMaximumRecordTtl: string
  cacheNegativeRecordTtl: string
  cacheFailureRecordTtl: string
  cachePrefetchEligibility: string
  cachePrefetchTrigger: string
  cachePrefetchSampleIntervalInMinutes: string
  cachePrefetchSampleEligibilityHitsPerHour: string

  // Blocking
  enableBlocking: boolean
  allowTxtBlockingReport: boolean
  temporaryDisableBlockingMinutes: string
  blockingBypassList: string
  blockingType: string
  customBlockingAddresses: string
  blockingAnswerTtl: string
  blockListUrls: string
  blockListUpdateIntervalHours: string

  // Proxy & Forwarders
  proxyType: string
  proxyAddress: string
  proxyPort: string
  proxyUsername: string
  proxyPassword: string
  proxyBypassList: string
  forwarders: string
  forwarderProtocol: string
  concurrentForwarding: boolean
  forwarderRetries: string
  forwarderTimeout: string
  forwarderConcurrency: string

  // Logging
  loggingType: string
  ignoreResolverLogs: boolean
  noStackTrace: boolean
  logQueries: boolean
  useLocalTime: boolean
  logFolder: string
  maxLogFileDays: string
  enableInMemoryStats: boolean
  maxStatFileDays: string
}

/*
`getArrayAsString` (main.js:1140) concatena cada entrada con `\r\n`, pero eso NO
es lo que acaba viajando al servidor: el HTML obliga al navegador a normalizar
los saltos del valor de un `<textarea>` a `\n` al leerlo, así que cuando
`cleanTextList` lo recoge los `\r` ya no están. Aquí no hay DOM intermedio que
normalice nada, de modo que se emite `\n` directamente. Copiar el `\r\n` literal
mandaría `forwarders=1.1.1.1%0D,8.8.8.8%0D` al servidor, que es justo lo que
upstream NO manda.
*/
export function listaATexto(lista: readonly string[] | number[] | null | undefined): string {
  if (lista == null) return ''
  return (lista as readonly (string | number)[]).map((v) => `${v}\n`).join('')
}

/** `cleanTextList` (common.js:326): saltos de línea a comas, comas repetidas
 *  colapsadas y comas de los extremos fuera. */
export function limpiarLista(texto: string): string {
  let t = texto.replace(/\n/g, ',')
  while (t.indexOf(',,') !== -1) t = t.replace(/,,/g, ',')
  if (t.startsWith(',')) t = t.substring(1)
  if (t.endsWith(',')) t = t.substring(0, t.length - 1)
  return t
}

export function formularioDesdeAjustes(s: DnsSettings): SettingsForm {
  return {
    dnsServerDomain: s.dnsServerDomain ?? '',
    dnsServerLocalEndPoints: listaATexto(s.dnsServerLocalEndPoints),
    dnsServerIPv4SourceAddresses: listaATexto(s.dnsServerIPv4SourceAddresses),
    dnsServerIPv6SourceAddresses: listaATexto(s.dnsServerIPv6SourceAddresses),

    defaultRecordTtl: String(s.defaultRecordTtl ?? ''),
    defaultNsRecordTtl: String(s.defaultNsRecordTtl ?? ''),
    defaultSoaRecordTtl: String(s.defaultSoaRecordTtl ?? ''),
    defaultResponsiblePerson: s.defaultResponsiblePerson ?? '',
    useSoaSerialDateScheme: s.useSoaSerialDateScheme,
    minSoaRefresh: String(s.minSoaRefresh ?? ''),
    minSoaRetry: String(s.minSoaRetry ?? ''),
    zoneTransferAllowedNetworks: listaATexto(s.zoneTransferAllowedNetworks),
    notifyAllowedNetworks: listaATexto(s.notifyAllowedNetworks),

    dnsServerEnableCheckForUpdate: s.dnsServerEnableCheckForUpdate,
    dnsAppsEnableAutomaticUpdate: s.dnsAppsEnableAutomaticUpdate,

    ipv6Mode: s.ipv6Mode ?? 'Disabled',
    enableUdpSocketPool: s.enableUdpSocketPool,
    socketPoolExcludedPorts: listaATexto(s.socketPoolExcludedPorts),

    udpPayloadSize: String(s.udpPayloadSize ?? ''),
    dnssecValidation: s.dnssecValidation,
    eDnsClientSubnet: s.eDnsClientSubnet,
    eDnsClientSubnetIPv4PrefixLength: String(s.eDnsClientSubnetIPv4PrefixLength ?? ''),
    eDnsClientSubnetIPv6PrefixLength: String(s.eDnsClientSubnetIPv6PrefixLength ?? ''),
    eDnsClientSubnetIpv4Override: s.eDnsClientSubnetIpv4Override ?? '',
    eDnsClientSubnetIpv6Override: s.eDnsClientSubnetIpv6Override ?? '',

    qpmPrefixLimitsIPv4: (s.qpmPrefixLimitsIPv4 ?? []).map(filaQpm),
    qpmPrefixLimitsIPv6: (s.qpmPrefixLimitsIPv6 ?? []).map(filaQpm),
    qpmLimitSampleMinutes: String(s.qpmLimitSampleMinutes ?? ''),
    qpmLimitUdpTruncationPercentage: String(s.qpmLimitUdpTruncationPercentage ?? ''),
    qpmLimitBypassList: listaATexto(s.qpmLimitBypassList),

    clientTimeout: String(s.clientTimeout ?? ''),
    tcpSendTimeout: String(s.tcpSendTimeout ?? ''),
    tcpReceiveTimeout: String(s.tcpReceiveTimeout ?? ''),
    quicIdleTimeout: String(s.quicIdleTimeout ?? ''),
    quicMaxInboundStreams: String(s.quicMaxInboundStreams ?? ''),
    listenBacklog: String(s.listenBacklog ?? ''),
    udpSendBufferSizeKB: String(s.udpSendBufferSizeKB ?? ''),
    udpReceiveBufferSizeKB: String(s.udpReceiveBufferSizeKB ?? ''),
    maxConcurrentResolutionsPerCore: String(s.maxConcurrentResolutionsPerCore ?? ''),

    webServiceLocalAddresses: listaATexto(s.webServiceLocalAddresses),
    webServiceHttpPort: String(s.webServiceHttpPort ?? ''),
    webServiceEnableHttpUnixSocket: s.webServiceEnableHttpUnixSocket,
    webServiceHttpUnixSocket: s.webServiceHttpUnixSocket ?? '',
    webServiceEnableTlsUnixSocket: s.webServiceEnableTlsUnixSocket,
    webServiceTlsUnixSocket: s.webServiceTlsUnixSocket ?? '',
    webServiceEnableTls: s.webServiceEnableTls,
    webServiceEnableHttp3: s.webServiceEnableHttp3,
    webServiceHttpToTlsRedirect: s.webServiceHttpToTlsRedirect,
    webServiceUseSelfSignedTlsCertificate: s.webServiceUseSelfSignedTlsCertificate,
    webServiceTlsPort: String(s.webServiceTlsPort ?? ''),
    webServiceReverseProxyAddresses: listaATexto(s.webServiceReverseProxyAddresses),
    webServiceRealIpHeader: s.webServiceRealIpHeader ?? '',
    webServiceCspFrameAncestorsHeader: s.webServiceCspFrameAncestorsHeader ?? '',
    webServiceTlsCertificatePath: s.webServiceTlsCertificatePath ?? '',
    webServiceTlsCertificatePassword: s.webServiceTlsCertificatePassword ?? '',

    enableEDnsClientSubnetSourceAddress: s.enableEDnsClientSubnetSourceAddress,
    enableDnsOverUdpProxy: s.enableDnsOverUdpProxy,
    enableDnsOverTcpProxy: s.enableDnsOverTcpProxy,
    enableDnsOverHttp: s.enableDnsOverHttp,
    enableDnsOverHttpUnixSocket: s.enableDnsOverHttpUnixSocket,
    enableDnsOverHttpsUnixSocket: s.enableDnsOverHttpsUnixSocket,
    enableDnsOverTls: s.enableDnsOverTls,
    enableDnsOverHttps: s.enableDnsOverHttps,
    enableDnsOverHttp3: s.enableDnsOverHttp3,
    enableDnsOverQuic: s.enableDnsOverQuic,
    enableDnsOverHttpHelpRedirect: s.enableDnsOverHttpHelpRedirect,
    dnsOverUdpProxyPort: String(s.dnsOverUdpProxyPort ?? ''),
    dnsOverTcpProxyPort: String(s.dnsOverTcpProxyPort ?? ''),
    dnsOverHttpPort: String(s.dnsOverHttpPort ?? ''),
    dnsOverHttpUnixSocket: s.dnsOverHttpUnixSocket ?? '',
    dnsOverHttpsUnixSocket: s.dnsOverHttpsUnixSocket ?? '',
    dnsOverTlsPort: String(s.dnsOverTlsPort ?? ''),
    dnsOverHttpsPort: String(s.dnsOverHttpsPort ?? ''),
    dnsOverQuicPort: String(s.dnsOverQuicPort ?? ''),
    dnsReverseProxyNetworkACL: listaATexto(s.dnsReverseProxyNetworkACL),
    dnsOverHttpRealIpHeader: s.dnsOverHttpRealIpHeader ?? '',
    dnsTlsCertificatePath: s.dnsTlsCertificatePath ?? '',
    dnsTlsCertificatePassword: s.dnsTlsCertificatePassword ?? '',

    tsigKeys: (s.tsigKeys ?? []).map((k) => ({
      keyName: k.keyName ?? '',
      sharedSecret: k.sharedSecret ?? '',
      algorithmName: k.algorithmName ?? 'hmac-sha256',
    })),

    recursion: s.recursion ?? 'Deny',
    recursionNetworkACL: listaATexto(s.recursionNetworkACL),
    randomizeName: s.randomizeName,
    qnameMinimization: s.qnameMinimization,
    locallyServedDnsZones: s.locallyServedDnsZones,
    resolverRetries: String(s.resolverRetries ?? ''),
    resolverTimeout: String(s.resolverTimeout ?? ''),
    resolverConcurrency: String(s.resolverConcurrency ?? ''),
    resolverMaxStackCount: String(s.resolverMaxStackCount ?? ''),

    saveCache: s.saveCache,
    serveStale: s.serveStale,
    serveStaleTtl: String(s.serveStaleTtl ?? ''),
    serveStaleAnswerTtl: String(s.serveStaleAnswerTtl ?? ''),
    serveStaleResetTtl: String(s.serveStaleResetTtl ?? ''),
    serveStaleMaxWaitTime: String(s.serveStaleMaxWaitTime ?? ''),
    cacheMaximumEntries: String(s.cacheMaximumEntries ?? ''),
    cacheMinimumRecordTtl: String(s.cacheMinimumRecordTtl ?? ''),
    cacheMaximumRecordTtl: String(s.cacheMaximumRecordTtl ?? ''),
    cacheNegativeRecordTtl: String(s.cacheNegativeRecordTtl ?? ''),
    cacheFailureRecordTtl: String(s.cacheFailureRecordTtl ?? ''),
    cachePrefetchEligibility: String(s.cachePrefetchEligibility ?? ''),
    cachePrefetchTrigger: String(s.cachePrefetchTrigger ?? ''),
    cachePrefetchSampleIntervalInMinutes: String(s.cachePrefetchSampleIntervalInMinutes ?? ''),
    cachePrefetchSampleEligibilityHitsPerHour: String(
      s.cachePrefetchSampleEligibilityHitsPerHour ?? '',
    ),

    enableBlocking: s.enableBlocking,
    allowTxtBlockingReport: s.allowTxtBlockingReport,
    // main.js:1455 — el campo de minutos se vacía en cada carga, no se conserva.
    temporaryDisableBlockingMinutes: '',
    blockingBypassList: listaATexto(s.blockingBypassList),
    blockingType: s.blockingType ?? 'AnyAddress',
    customBlockingAddresses: listaATexto(s.customBlockingAddresses),
    blockingAnswerTtl: String(s.blockingAnswerTtl ?? ''),
    blockListUrls: listaATexto(s.blockListUrls),
    blockListUpdateIntervalHours: String(s.blockListUpdateIntervalHours ?? ''),

    // main.js:1525 — el tipo de proxy se compara en minúsculas y cualquier
    // valor desconocido cae en «None».
    proxyType: tipoProxy(s.proxy?.type),
    proxyAddress: s.proxy?.address ?? '',
    proxyPort: s.proxy == null ? '' : String(s.proxy.port ?? ''),
    proxyUsername: s.proxy?.username ?? '',
    proxyPassword: s.proxy?.password ?? '',
    proxyBypassList: listaATexto(s.proxy?.bypass),
    forwarders: listaATexto(s.forwarders),
    forwarderProtocol: s.forwarderProtocol ?? 'Udp',
    concurrentForwarding: s.concurrentForwarding,
    forwarderRetries: String(s.forwarderRetries ?? ''),
    forwarderTimeout: String(s.forwarderTimeout ?? ''),
    forwarderConcurrency: String(s.forwarderConcurrency ?? ''),

    loggingType: s.loggingType ?? 'None',
    ignoreResolverLogs: s.ignoreResolverLogs,
    noStackTrace: s.noStackTrace,
    logQueries: s.logQueries,
    useLocalTime: s.useLocalTime,
    logFolder: s.logFolder ?? '',
    maxLogFileDays: String(s.maxLogFileDays ?? ''),
    enableInMemoryStats: s.enableInMemoryStats,
    maxStatFileDays: String(s.maxStatFileDays ?? ''),
  }
}

function filaQpm(l: { prefix: number; udpLimit: number; tcpLimit: number }): QpmRow {
  return { prefix: String(l.prefix), udpLimit: String(l.udpLimit), tcpLimit: String(l.tcpLimit) }
}

function tipoProxy(tipo: string | undefined): string {
  switch ((tipo ?? '').toLowerCase()) {
    case 'http':
      return 'Http'
    case 'socks5':
      return 'Socks5'
    default:
      return 'None'
  }
}

/* ── Reglas de habilitado ──────────────────────────────────────────────────
   Upstream las reparte entre `loadDnsSettings` y una docena de manejadores de
   `click`/`change` en `$(function(){…})` (main.js:279-490). Al derivarlas del
   estado en vez de mutarlas por evento, la regla vive en un solo sitio y no se
   puede quedar desincronizada, que es lo que le pasa hoy a upstream con
   `chkEnableDnsOverHttp3` (ver el informe de esta fase).                    */
export function habilitado(f: SettingsForm) {
  const tlsWeb = f.webServiceEnableTls || f.webServiceEnableTlsUnixSocket
  const proxyInverso =
    f.enableEDnsClientSubnetSourceAddress ||
    f.enableDnsOverUdpProxy ||
    f.enableDnsOverTcpProxy ||
    f.enableDnsOverHttp ||
    f.enableDnsOverHttps
  const doh =
    f.enableDnsOverHttpUnixSocket ||
    f.enableDnsOverHttpsUnixSocket ||
    f.enableDnsOverHttp ||
    f.enableDnsOverHttps
  const certDns =
    f.enableDnsOverTls || f.enableDnsOverHttps || f.enableDnsOverQuic || f.enableDnsOverHttpsUnixSocket

  return {
    socketPoolExcludedPorts: f.enableUdpSocketPool,
    ecs: f.eDnsClientSubnet,

    webServiceHttpUnixSocket: f.webServiceEnableHttpUnixSocket,
    webServiceTlsUnixSocket: f.webServiceEnableTlsUnixSocket,
    webServiceEnableHttp3: f.webServiceEnableTls,
    webServiceHttpToTlsRedirect: f.webServiceEnableTls,
    webServiceTlsPort: f.webServiceEnableTls,
    webServiceTlsCert: tlsWeb,

    dnsOverUdpProxyPort: f.enableDnsOverUdpProxy,
    dnsOverTcpProxyPort: f.enableDnsOverTcpProxy,
    dnsOverHttpPort: f.enableDnsOverHttp,
    dnsOverHttpUnixSocket: f.enableDnsOverHttpUnixSocket,
    dnsOverHttpsUnixSocket: f.enableDnsOverHttpsUnixSocket,
    dnsOverTlsPort: f.enableDnsOverTls,
    dnsOverHttpsPort: f.enableDnsOverHttps,
    dnsOverQuicPort: f.enableDnsOverQuic,
    enableDnsOverHttp3: f.enableDnsOverHttps,
    dnsReverseProxyNetworkACL: proxyInverso,
    dnsOverHttpRealIpHeader: doh,
    dnsTlsCert: certDns,

    recursionNetworkACL: f.recursion === 'UseSpecifiedNetworkACL',
    serveStale: f.serveStale,
    blocking: f.enableBlocking,
    customBlockingAddresses: f.enableBlocking && f.blockingType === 'CustomAddress',
    actualizarListasAhora: f.enableBlocking && f.blockListUrls !== '',
    proxy: f.proxyType !== 'None',
    forwarderConcurrency: f.concurrentForwarding,
    logging: f.loggingType.toLowerCase() !== 'none',
  }
}

/* ── Construcción del cuerpo de `settings/set` ─────────────────────────── */

export interface ErrorValidacion {
  title: string
  text: string
  /** Sub-pestaña en la que está el campo, para poder saltar a ella. */
  tab: string
  /** `name` del control, para devolverle el foco como hace upstream. */
  campo: string
}

export interface ResultadoCuerpo {
  error?: ErrorValidacion
  body?: Record<string, string>
  /** Textareas que upstream reescribe con la lista saneada. */
  saneado?: Partial<SettingsForm>
}

/** `serializeTableData` (common.js:282): todas las celdas unidas por `|`.
 *  Sólo `sharedSecret` lleva `data-optional`, así que sólo ella admite vacío. */
function serializarTabla(
  filas: { valor: string; opcional?: boolean }[][],
  tab: string,
  campo: string,
): { valor: string } | { error: ErrorValidacion } {
  const salida: string[] = []
  for (const fila of filas) {
    for (const celda of fila) {
      if (celda.valor === '' && celda.opcional !== true) {
        return {
          error: {
            title: 'Missing!',
            text: 'Please enter a valid value in the text field in focus.',
            tab,
            campo,
          },
        }
      }
      if (celda.valor.includes('|')) {
        return {
          error: {
            title: 'Invalid Character!',
            text: "Please edit the value in the text field in focus to remove '|' character.",
            tab,
            campo,
          },
        }
      }
      salida.push(celda.valor)
    }
  }
  return { valor: salida.join('|') }
}

export function construirCuerpo(f: SettingsForm, node = ''): ResultadoCuerpo {
  const body: Record<string, string> = { node }
  const saneado: Partial<SettingsForm> = {}

  const falta = (text: string, tab: string, campo: string): ResultadoCuerpo => ({
    error: { title: 'Missing!', text, tab, campo },
  })

  // ── General: parámetros locales
  if (f.dnsServerDomain === '') {
    return falta('Please enter server domain name.', 'General', 'dnsServerDomain')
  }

  let dnsServerLocalEndPoints = limpiarLista(f.dnsServerLocalEndPoints)
  if (dnsServerLocalEndPoints.length === 0 || dnsServerLocalEndPoints === ',') {
    dnsServerLocalEndPoints = '0.0.0.0:53,[::]:53'
  } else {
    saneado.dnsServerLocalEndPoints = dnsServerLocalEndPoints.replace(/,/g, '\n')
  }

  const v4 = limpiarLista(f.dnsServerIPv4SourceAddresses)
  const v6 = limpiarLista(f.dnsServerIPv6SourceAddresses)

  body.dnsServerDomain = f.dnsServerDomain
  body.dnsServerLocalEndPoints = dnsServerLocalEndPoints
  body.dnsServerIPv4SourceAddresses = v4.length === 0 || v4 === ',' ? 'false' : v4
  body.dnsServerIPv6SourceAddresses = v6.length === 0 || v6 === ',' ? 'false' : v6

  // ── General: valores por defecto
  const zta = limpiarLista(f.zoneTransferAllowedNetworks)
  const nan = limpiarLista(f.notifyAllowedNetworks)
  if (!(zta.length === 0 || zta === ',')) saneado.zoneTransferAllowedNetworks = zta.replace(/,/g, '\n') + '\n'
  if (!(nan.length === 0 || nan === ',')) saneado.notifyAllowedNetworks = nan.replace(/,/g, '\n') + '\n'

  body.defaultRecordTtl = f.defaultRecordTtl
  body.defaultNsRecordTtl = f.defaultNsRecordTtl
  body.defaultSoaRecordTtl = f.defaultSoaRecordTtl
  body.defaultResponsiblePerson = f.defaultResponsiblePerson
  body.useSoaSerialDateScheme = String(f.useSoaSerialDateScheme)
  body.minSoaRefresh = f.minSoaRefresh
  body.minSoaRetry = f.minSoaRetry
  body.zoneTransferAllowedNetworks = zta.length === 0 || zta === ',' ? 'false' : zta
  body.notifyAllowedNetworks = nan.length === 0 || nan === ',' ? 'false' : nan
  body.dnsServerEnableCheckForUpdate = String(f.dnsServerEnableCheckForUpdate)
  body.dnsAppsEnableAutomaticUpdate = String(f.dnsAppsEnableAutomaticUpdate)

  // ── General: IPv6 y socket pool
  const spep = limpiarLista(f.socketPoolExcludedPorts)
  if (!(spep.length === 0 || spep === ',')) saneado.socketPoolExcludedPorts = spep.replace(/,/g, '\n') + '\n'

  body.ipv6Mode = f.ipv6Mode
  body.enableUdpSocketPool = String(f.enableUdpSocketPool)
  body.socketPoolExcludedPorts = spep.length === 0 || spep === ',' ? 'false' : spep

  // ── General: EDNS / DNSSEC / ECS
  if (f.eDnsClientSubnetIPv4PrefixLength === '') {
    return falta(
      'Please enter EDNS Client Subnet IPv4 prefix length.',
      'General',
      'eDnsClientSubnetIPv4PrefixLength',
    )
  }
  if (f.eDnsClientSubnetIPv6PrefixLength === '') {
    return falta(
      'Please enter EDNS Client Subnet IPv6 prefix length.',
      'General',
      'eDnsClientSubnetIPv6PrefixLength',
    )
  }

  // ── General: QPM
  const qpm4 = serializarTabla(
    f.qpmPrefixLimitsIPv4.map((r) => [
      { valor: r.prefix },
      { valor: r.udpLimit },
      { valor: r.tcpLimit },
    ]),
    'General',
    'qpmPrefixLimitsIPv4',
  )
  if ('error' in qpm4) return { error: qpm4.error }

  const qpm6 = serializarTabla(
    f.qpmPrefixLimitsIPv6.map((r) => [
      { valor: r.prefix },
      { valor: r.udpLimit },
      { valor: r.tcpLimit },
    ]),
    'General',
    'qpmPrefixLimitsIPv6',
  )
  if ('error' in qpm6) return { error: qpm6.error }

  if (f.qpmLimitSampleMinutes === '') {
    return falta(
      'Please enter Queries Per Minute (QPM) sample value.',
      'General',
      'qpmLimitSampleMinutes',
    )
  }
  if (f.qpmLimitUdpTruncationPercentage === '') {
    return falta(
      'Please enter Queries Per Minute (QPM) limit UDP truncation percentage value.',
      'General',
      'qpmLimitUdpTruncationPercentage',
    )
  }

  const qbl = limpiarLista(f.qpmLimitBypassList)
  if (!(qbl.length === 0 || qbl === ',')) saneado.qpmLimitBypassList = qbl.replace(/,/g, '\n') + '\n'

  // ── General: avanzado
  const obligatorios: [keyof SettingsForm, string, string][] = [
    ['clientTimeout', 'Please enter a value for Client Timeout.', 'clientTimeout'],
    ['tcpSendTimeout', 'Please enter a value for TCP Send Timeout.', 'tcpSendTimeout'],
    ['tcpReceiveTimeout', 'Please enter a value for TCP Receive Timeout.', 'tcpReceiveTimeout'],
    ['quicIdleTimeout', 'Please enter a value for QUIC Idle Timeout.', 'quicIdleTimeout'],
    ['quicMaxInboundStreams', 'Please enter a value for QUIC Max Inbound Streams.', 'quicMaxInboundStreams'],
    ['listenBacklog', 'Please enter a value for Listen Backlog.', 'listenBacklog'],
    ['udpSendBufferSizeKB', 'Please enter a value for UDP Send Buffer Size.', 'udpSendBufferSizeKB'],
    ['udpReceiveBufferSizeKB', 'Please enter a value for UDP Receive Buffer Size.', 'udpReceiveBufferSizeKB'],
    ['maxConcurrentResolutionsPerCore', 'Please enter a value for Max Concurrent Resolutions.', 'maxConcurrentResolutionsPerCore'],
  ]
  for (const [clave, texto, campo] of obligatorios) {
    if (f[clave] === '') return falta(texto, 'General', campo)
  }

  body.udpPayloadSize = f.udpPayloadSize
  body.dnssecValidation = String(f.dnssecValidation)
  body.eDnsClientSubnet = String(f.eDnsClientSubnet)
  body.eDnsClientSubnetIPv4PrefixLength = f.eDnsClientSubnetIPv4PrefixLength
  body.eDnsClientSubnetIPv6PrefixLength = f.eDnsClientSubnetIPv6PrefixLength
  body.eDnsClientSubnetIpv4Override = f.eDnsClientSubnetIpv4Override
  body.eDnsClientSubnetIpv6Override = f.eDnsClientSubnetIpv6Override
  body.qpmPrefixLimitsIPv4 = qpm4.valor.length === 0 ? 'false' : qpm4.valor
  body.qpmPrefixLimitsIPv6 = qpm6.valor.length === 0 ? 'false' : qpm6.valor
  body.qpmLimitSampleMinutes = f.qpmLimitSampleMinutes
  body.qpmLimitUdpTruncationPercentage = f.qpmLimitUdpTruncationPercentage
  body.qpmLimitBypassList = qbl.length === 0 || qbl === ',' ? 'false' : qbl
  body.clientTimeout = f.clientTimeout
  body.tcpSendTimeout = f.tcpSendTimeout
  body.tcpReceiveTimeout = f.tcpReceiveTimeout
  body.quicIdleTimeout = f.quicIdleTimeout
  body.quicMaxInboundStreams = f.quicMaxInboundStreams
  body.listenBacklog = f.listenBacklog
  body.udpSendBufferSizeKB = f.udpSendBufferSizeKB
  body.udpReceiveBufferSizeKB = f.udpReceiveBufferSizeKB
  body.maxConcurrentResolutionsPerCore = f.maxConcurrentResolutionsPerCore

  // ── Web Service (sin validación: los vacíos caen a su valor por defecto)
  let wsla = limpiarLista(f.webServiceLocalAddresses)
  if (wsla.length === 0 || wsla === ',') wsla = '0.0.0.0,[::]'
  else saneado.webServiceLocalAddresses = wsla.replace(/,/g, '\n')

  const wsrpa = limpiarLista(f.webServiceReverseProxyAddresses)
  if (!(wsrpa.length === 0 || wsrpa === ',')) {
    saneado.webServiceReverseProxyAddresses = wsrpa.replace(/,/g, '\n')
  }

  body.webServiceLocalAddresses = wsla
  body.webServiceHttpPort = f.webServiceHttpPort === '' ? '5380' : f.webServiceHttpPort
  body.webServiceEnableHttpUnixSocket = String(f.webServiceEnableHttpUnixSocket)
  body.webServiceHttpUnixSocket = f.webServiceHttpUnixSocket
  body.webServiceEnableTlsUnixSocket = String(f.webServiceEnableTlsUnixSocket)
  body.webServiceTlsUnixSocket = f.webServiceTlsUnixSocket
  body.webServiceEnableTls = String(f.webServiceEnableTls)
  body.webServiceEnableHttp3 = String(f.webServiceEnableHttp3)
  body.webServiceHttpToTlsRedirect = String(f.webServiceHttpToTlsRedirect)
  body.webServiceUseSelfSignedTlsCertificate = String(f.webServiceUseSelfSignedTlsCertificate)
  body.webServiceTlsPort = f.webServiceTlsPort
  body.webServiceReverseProxyAddresses = wsrpa.length === 0 || wsrpa === ',' ? 'false' : wsrpa
  body.webServiceRealIpHeader = f.webServiceRealIpHeader
  body.webServiceCspFrameAncestorsHeader = f.webServiceCspFrameAncestorsHeader
  body.webServiceTlsCertificatePath = f.webServiceTlsCertificatePath
  body.webServiceTlsCertificatePassword = f.webServiceTlsCertificatePassword

  // ── Optional Protocols
  const puertos: [keyof SettingsForm, string, string][] = [
    ['dnsOverUdpProxyPort', 'Please enter a value for DNS-over-UDP-PROXY Port.', 'dnsOverUdpProxyPort'],
    ['dnsOverTcpProxyPort', 'Please enter a value for DNS-over-TCP-PROXY Port.', 'dnsOverTcpProxyPort'],
    ['dnsOverHttpPort', 'Please enter a value for DNS-over-HTTP Port.', 'dnsOverHttpPort'],
    ['dnsOverTlsPort', 'Please enter a value for DNS-over-TLS Port.', 'dnsOverTlsPort'],
    ['dnsOverHttpsPort', 'Please enter a value for DNS-over-HTTPS Port.', 'dnsOverHttpsPort'],
    ['dnsOverQuicPort', 'Please enter a value for DNS-over-QUIC Port.', 'dnsOverQuicPort'],
  ]
  for (const [clave, texto, campo] of puertos) {
    if (f[clave] === '') return falta(texto, 'Optional Protocols', campo)
  }

  const drpa = limpiarLista(f.dnsReverseProxyNetworkACL)
  if (!(drpa.length === 0 || drpa === ',')) {
    saneado.dnsReverseProxyNetworkACL = drpa.replace(/,/g, '\n')
  }

  body.enableEDnsClientSubnetSourceAddress = String(f.enableEDnsClientSubnetSourceAddress)
  body.enableDnsOverUdpProxy = String(f.enableDnsOverUdpProxy)
  body.enableDnsOverTcpProxy = String(f.enableDnsOverTcpProxy)
  body.enableDnsOverHttp = String(f.enableDnsOverHttp)
  body.enableDnsOverHttpUnixSocket = String(f.enableDnsOverHttpUnixSocket)
  body.enableDnsOverHttpsUnixSocket = String(f.enableDnsOverHttpsUnixSocket)
  body.enableDnsOverTls = String(f.enableDnsOverTls)
  body.enableDnsOverHttps = String(f.enableDnsOverHttps)
  body.enableDnsOverHttp3 = String(f.enableDnsOverHttp3)
  body.enableDnsOverQuic = String(f.enableDnsOverQuic)
  body.enableDnsOverHttpHelpRedirect = String(f.enableDnsOverHttpHelpRedirect)
  body.dnsOverUdpProxyPort = f.dnsOverUdpProxyPort
  body.dnsOverTcpProxyPort = f.dnsOverTcpProxyPort
  body.dnsOverHttpPort = f.dnsOverHttpPort
  body.dnsOverHttpUnixSocket = f.dnsOverHttpUnixSocket
  body.dnsOverHttpsUnixSocket = f.dnsOverHttpsUnixSocket
  body.dnsOverTlsPort = f.dnsOverTlsPort
  body.dnsOverHttpsPort = f.dnsOverHttpsPort
  body.dnsOverQuicPort = f.dnsOverQuicPort
  body.dnsReverseProxyNetworkACL = drpa.length === 0 || drpa === ',' ? 'false' : drpa
  body.dnsOverHttpRealIpHeader = f.dnsOverHttpRealIpHeader
  body.dnsTlsCertificatePath = f.dnsTlsCertificatePath
  body.dnsTlsCertificatePassword = f.dnsTlsCertificatePassword

  // ── TSIG
  const tsig = serializarTabla(
    f.tsigKeys.map((k) => [
      { valor: k.keyName },
      { valor: k.sharedSecret, opcional: true },
      { valor: k.algorithmName },
    ]),
    'TSIG',
    'tsigKeys',
  )
  if ('error' in tsig) return { error: tsig.error }
  body.tsigKeys = tsig.valor.length === 0 ? 'false' : tsig.valor

  // ── Recursion
  const racl = limpiarLista(f.recursionNetworkACL)
  if (!(racl.length === 0 || racl === ',')) saneado.recursionNetworkACL = racl.replace(/,/g, '\n')

  const resolutor: [keyof SettingsForm, string, string][] = [
    ['resolverRetries', 'Please enter a value for Resolver Retries.', 'resolverRetries'],
    ['resolverTimeout', 'Please enter a value for Resolver Timeout.', 'resolverTimeout'],
    ['resolverConcurrency', 'Please enter a value for Resolver Concurrency.', 'resolverConcurrency'],
    ['resolverMaxStackCount', 'Please enter a value for Resolver Max Stack Count.', 'resolverMaxStackCount'],
  ]
  for (const [clave, texto, campo] of resolutor) {
    if (f[clave] === '') return falta(texto, 'Recursion', campo)
  }

  body.recursion = f.recursion
  body.recursionNetworkACL = racl.length === 0 || racl === ',' ? 'false' : racl
  body.randomizeName = String(f.randomizeName)
  body.qnameMinimization = String(f.qnameMinimization)
  body.locallyServedDnsZones = String(f.locallyServedDnsZones)
  body.resolverRetries = f.resolverRetries
  body.resolverTimeout = f.resolverTimeout
  body.resolverConcurrency = f.resolverConcurrency
  body.resolverMaxStackCount = f.resolverMaxStackCount

  // ── Cache
  const cache: [keyof SettingsForm, string, string][] = [
    ['cacheMaximumEntries', 'Please enter cache maximum entries value.', 'cacheMaximumEntries'],
    ['cacheMinimumRecordTtl', 'Please enter cache minimum record TTL value.', 'cacheMinimumRecordTtl'],
    ['cacheMaximumRecordTtl', 'Please enter cache maximum record TTL value.', 'cacheMaximumRecordTtl'],
    ['cacheNegativeRecordTtl', 'Please enter cache negative record TTL value.', 'cacheNegativeRecordTtl'],
    ['cacheFailureRecordTtl', 'Please enter cache failure record TTL value.', 'cacheFailureRecordTtl'],
    ['cachePrefetchEligibility', 'Please enter cache prefetch eligibility value.', 'cachePrefetchEligibility'],
    ['cachePrefetchTrigger', 'Please enter cache prefetch trigger value.', 'cachePrefetchTrigger'],
    ['cachePrefetchSampleIntervalInMinutes', 'Please enter cache auto prefetch sample interval value.', 'cachePrefetchSampleIntervalInMinutes'],
    ['cachePrefetchSampleEligibilityHitsPerHour', 'Please enter cache auto prefetch sample eligibility value.', 'cachePrefetchSampleEligibilityHitsPerHour'],
  ]
  for (const [clave, texto, campo] of cache) {
    if (f[clave] === '') return falta(texto, 'Cache', campo)
  }

  body.saveCache = String(f.saveCache)
  body.serveStale = String(f.serveStale)
  body.serveStaleTtl = f.serveStaleTtl
  body.serveStaleAnswerTtl = f.serveStaleAnswerTtl
  body.serveStaleResetTtl = f.serveStaleResetTtl
  body.serveStaleMaxWaitTime = f.serveStaleMaxWaitTime
  body.cacheMaximumEntries = f.cacheMaximumEntries
  body.cacheMinimumRecordTtl = f.cacheMinimumRecordTtl
  body.cacheMaximumRecordTtl = f.cacheMaximumRecordTtl
  body.cacheNegativeRecordTtl = f.cacheNegativeRecordTtl
  body.cacheFailureRecordTtl = f.cacheFailureRecordTtl
  body.cachePrefetchEligibility = f.cachePrefetchEligibility
  body.cachePrefetchTrigger = f.cachePrefetchTrigger
  body.cachePrefetchSampleIntervalInMinutes = f.cachePrefetchSampleIntervalInMinutes
  body.cachePrefetchSampleEligibilityHitsPerHour = f.cachePrefetchSampleEligibilityHitsPerHour

  // ── Blocking (sin validación en upstream)
  const bbl = limpiarLista(f.blockingBypassList)
  if (!(bbl.length === 0 || bbl === ',')) saneado.blockingBypassList = bbl.replace(/,/g, '\n') + '\n'

  const cba = limpiarLista(f.customBlockingAddresses)
  if (!(cba.length === 0 || cba === ',')) saneado.customBlockingAddresses = cba.replace(/,/g, '\n') + '\n'

  const blu = limpiarLista(f.blockListUrls)
  if (!(blu.length === 0 || blu === ',')) saneado.blockListUrls = blu.replace(/,/g, '\n') + '\n'

  body.enableBlocking = String(f.enableBlocking)
  body.allowTxtBlockingReport = String(f.allowTxtBlockingReport)
  body.blockingBypassList = bbl.length === 0 || bbl === ',' ? 'false' : bbl
  body.blockingType = f.blockingType
  body.customBlockingAddresses = cba.length === 0 || cba === ',' ? 'false' : cba
  body.blockingAnswerTtl = f.blockingAnswerTtl
  body.blockListUrls = blu.length === 0 || blu === ',' ? 'false' : blu
  body.blockListUpdateIntervalHours = f.blockListUpdateIntervalHours

  // ── Proxy & Forwarders
  const proxyType = f.proxyType.toLowerCase()
  const proxy: Record<string, string> = { proxyType }
  if (proxyType !== 'none') {
    if (f.proxyAddress === '') {
      return falta('Please enter proxy server address.', 'Proxy & Forwarders', 'proxyAddress')
    }
    if (f.proxyPort === '') {
      return falta('Please enter proxy server port.', 'Proxy & Forwarders', 'proxyPort')
    }
    const pb = limpiarLista(f.proxyBypassList)
    // main.js:2145 — aquí el vacío NO es «false», es cadena vacía.
    if (!(pb.length === 0 || pb === ',')) saneado.proxyBypassList = pb.replace(/,/g, '\n')

    proxy.proxyAddress = f.proxyAddress
    proxy.proxyPort = f.proxyPort
    proxy.proxyUsername = f.proxyUsername
    proxy.proxyPassword = f.proxyPassword
    proxy.proxyBypass = pb.length === 0 || pb === ',' ? '' : pb
  }

  const fwd = limpiarLista(f.forwarders)
  if (!(fwd.length === 0 || fwd === ',')) saneado.forwarders = fwd.replace(/,/g, '\n')

  const reenvio: [keyof SettingsForm, string, string][] = [
    ['forwarderRetries', 'Please enter a value for Forwarder Retries.', 'forwarderRetries'],
    ['forwarderTimeout', 'Please enter a value for Forwarder Timeout.', 'forwarderTimeout'],
    ['forwarderConcurrency', 'Please enter a value for Forwarder Concurrency.', 'forwarderConcurrency'],
  ]
  for (const [clave, texto, campo] of reenvio) {
    if (f[clave] === '') return falta(texto, 'Proxy & Forwarders', campo)
  }

  Object.assign(body, proxy)
  body.forwarders = fwd.length === 0 || fwd === ',' ? 'false' : fwd
  body.forwarderProtocol = f.forwarderProtocol
  body.concurrentForwarding = String(f.concurrentForwarding)
  body.forwarderRetries = f.forwarderRetries
  body.forwarderTimeout = f.forwarderTimeout
  body.forwarderConcurrency = f.forwarderConcurrency

  // ── Logging (sin validación en upstream)
  body.loggingType = f.loggingType
  body.ignoreResolverLogs = String(f.ignoreResolverLogs)
  body.noStackTrace = String(f.noStackTrace)
  body.logQueries = String(f.logQueries)
  body.useLocalTime = String(f.useLocalTime)
  body.logFolder = f.logFolder
  body.maxLogFileDays = f.maxLogFileDays
  body.enableInMemoryStats = String(f.enableInMemoryStats)
  body.maxStatFileDays = f.maxStatFileDays

  return { body, saneado }
}
