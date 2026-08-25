import { apiRequest, type ApiOutcome } from './client'

/*
La familia `settings`. Seis endpoints salen de la consola antigua:

  settings/get                      main.js:891  (refreshDnsSettings)
  settings/set                      main.js:2189 (saveDnsSettings, POST)
  settings/forceUpdateBlockLists    main.js:2346
  settings/temporaryDisableBlocking main.js:2373
  settings/backup                   main.js:3067 (descarga, token de un solo uso)
  settings/restore                  main.js:3137 (POST multipart)

El séptimo control de la pantalla, «Flush Cache», NO es de esta familia: llama a
`cache/flush` (other-zones.js:20). Se declara aquí porque la barra de acciones de
Settings es su único consumidor hasta que llegue la fase 5 con `src/api/cache.ts`;
cuando exista, se mueve allí.

Tres cosas comprobadas contra una instancia v15.4 y que NO se deducen del código:

  1. `settings/get` OMITE las claves nulas en vez de mandarlas a null. Con la
     instalación recién hecha no aparecen ni `temporaryDisableBlockingTill`, ni
     `blockListNextUpdatedOn`, ni `clusterNodes`. Por eso son opcionales aquí y
     `loadDnsSettings` las compara con `== null`: ausente y null valen igual.
     En cambio `blockListUrls`, `proxy`, `defaultResponsiblePerson` y los cuatro
     caminos de certificado sí llegan explícitamente a `null`.
  2. `proxy` es un objeto anidado (`type`/`address`/`port`/`username`/`password`/
     `bypass`) al leer, pero al guardar se manda PLANO: `proxyType`,
     `proxyAddress`… Y cuando el tipo es `none` NO se manda ningún otro campo
     de proxy (main.js:2122-2123): la lista de bypass se pierde a propósito.
  3. `settings/set` devuelve los ajustes completos, igual que `get`, y upstream
     los usa para repintar el formulario. Así se ve el saneado del servidor.
*/

export interface QpmPrefixLimit {
  prefix: number
  udpLimit: number
  tcpLimit: number
}

export interface TsigKey {
  keyName: string
  sharedSecret: string
  algorithmName: string
}

export interface NetProxy {
  type: string
  address: string
  port: number
  username: string
  password: string
  bypass: string[]
}

export interface DnsSettings {
  version: string
  uptimestamp: string
  clusterInitialized?: boolean
  clusterNodes?: string[]

  // General — parámetros locales
  dnsServerDomain: string
  dnsServerLocalEndPoints: string[] | null
  dnsServerIPv4SourceAddresses: string[] | null
  dnsServerIPv6SourceAddresses: string[] | null

  // General — valores por defecto de zona
  defaultRecordTtl: number
  defaultNsRecordTtl: number
  defaultSoaRecordTtl: number
  defaultResponsiblePerson: string | null
  useSoaSerialDateScheme: boolean
  minSoaRefresh: number
  minSoaRetry: number
  zoneTransferAllowedNetworks: string[]
  notifyAllowedNetworks: string[]

  // General — actualización de software
  dnsServerEnableCheckForUpdate: boolean
  dnsAppsEnableAutomaticUpdate: boolean

  // General — IPv6 y socket pool
  ipv6Mode: string
  preferIPv6: boolean
  enableUdpSocketPool: boolean
  socketPoolExcludedPorts: number[]

  // General — EDNS, DNSSEC y ECS
  udpPayloadSize: number
  dnssecValidation: boolean
  eDnsClientSubnet: boolean
  eDnsClientSubnetIPv4PrefixLength: number
  eDnsClientSubnetIPv6PrefixLength: number
  eDnsClientSubnetIpv4Override: string | null
  eDnsClientSubnetIpv6Override: string | null

  // General — límite de consultas por minuto
  qpmPrefixLimitsIPv4: QpmPrefixLimit[]
  qpmPrefixLimitsIPv6: QpmPrefixLimit[]
  qpmLimitSampleMinutes: number
  qpmLimitUdpTruncationPercentage: number
  qpmLimitBypassList: string[]

  // General — opciones avanzadas
  clientTimeout: number
  tcpSendTimeout: number
  tcpReceiveTimeout: number
  quicIdleTimeout: number
  quicMaxInboundStreams: number
  listenBacklog: number
  udpSendBufferSizeKB: number
  udpReceiveBufferSizeKB: number
  maxConcurrentResolutionsPerCore: number

  // Web Service
  webServiceLocalAddresses: string[]
  webServiceHttpPort: number
  webServiceEnableHttpUnixSocket: boolean
  webServiceHttpUnixSocket: string | null
  webServiceEnableTlsUnixSocket: boolean
  webServiceTlsUnixSocket: string | null
  webServiceEnableTls: boolean
  webServiceEnableHttp3: boolean
  webServiceHttpToTlsRedirect: boolean
  webServiceUseSelfSignedTlsCertificate: boolean
  webServiceTlsPort: number
  webServiceReverseProxyAddresses: string[]
  webServiceRealIpHeader: string
  webServiceCspFrameAncestorsHeader: string
  webServiceTlsCertificatePath: string | null
  webServiceTlsCertificatePassword: string | null

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
  dnsOverUdpProxyPort: number
  dnsOverTcpProxyPort: number
  dnsOverHttpPort: number
  dnsOverHttpUnixSocket: string | null
  dnsOverHttpsUnixSocket: string | null
  dnsOverTlsPort: number
  dnsOverHttpsPort: number
  dnsOverQuicPort: number
  dnsReverseProxyNetworkACL: string[]
  dnsOverHttpRealIpHeader: string
  dnsTlsCertificatePath: string | null
  dnsTlsCertificatePassword: string | null

  // TSIG
  tsigKeys: TsigKey[] | null

  // Recursion
  recursion: string
  recursionNetworkACL: string[]
  randomizeName: boolean
  qnameMinimization: boolean
  locallyServedDnsZones: boolean
  resolverRetries: number
  resolverTimeout: number
  resolverConcurrency: number
  resolverMaxStackCount: number

  // Cache
  saveCache: boolean
  serveStale: boolean
  serveStaleTtl: number
  serveStaleAnswerTtl: number
  serveStaleResetTtl: number
  serveStaleMaxWaitTime: number
  cacheMaximumEntries: number
  cacheMinimumRecordTtl: number
  cacheMaximumRecordTtl: number
  cacheNegativeRecordTtl: number
  cacheFailureRecordTtl: number
  cachePrefetchEligibility: number
  cachePrefetchTrigger: number
  cachePrefetchSampleIntervalInMinutes: number
  cachePrefetchSampleEligibilityHitsPerHour: number

  // Blocking
  enableBlocking: boolean
  allowTxtBlockingReport: boolean
  temporaryDisableBlockingTill?: string | null
  blockingBypassList: string[]
  blockingType: string
  blockingAnswerTtl: number
  customBlockingAddresses: string[]
  blockListUrls: string[] | null
  blockListUpdateIntervalHours: number
  blockListNextUpdatedOn?: string | null

  // Proxy & Forwarders
  proxy: NetProxy | null
  forwarders: string[] | null
  forwarderProtocol: string
  concurrentForwarding: boolean
  forwarderRetries: number
  forwarderTimeout: number
  forwarderConcurrency: number

  // Logging
  enableLogging: boolean
  loggingType: string
  ignoreResolverLogs: boolean
  logQueries: boolean
  noStackTrace: boolean
  useLocalTime: boolean
  logFolder: string
  maxLogFileDays: number
  enableInMemoryStats: boolean
  maxStatFileDays: number
}

/** `settings/get`. `node` existe para el modo clúster; con una sola instancia
 *  upstream manda la cadena vacía y el servidor responde con sus propios ajustes. */
export async function getSettings(
  token: string | null,
  node = '',
): Promise<DnsSettings | null> {
  const outcome = await apiRequest<{ response: DnsSettings }>('settings/get', {
    token,
    body: { node },
  })
  return outcome.kind === 'ok' ? outcome.data.response : null
}

/** `settings/set`. Va por POST con el cuerpo urlencoded, igual que upstream, y
 *  devuelve los ajustes ya saneados por el servidor para repintar el formulario.
 *  Se devuelve el `ApiOutcome` entero porque la pantalla necesita el
 *  `errorMessage` del servidor para el aviso `Error!`. */
export async function setSettings(
  token: string | null,
  body: Record<string, string>,
): Promise<ApiOutcome<{ response: DnsSettings }>> {
  return apiRequest<{ response: DnsSettings }>('settings/set', {
    token,
    method: 'POST',
    body,
  })
}

/** `settings/forceUpdateBlockLists`. Sin parámetros: fuerza la descarga ya. */
export async function forceUpdateBlockLists(token: string | null): Promise<boolean> {
  const outcome = await apiRequest('settings/forceUpdateBlockLists', { token })
  return outcome.kind === 'ok'
}

/** `settings/temporaryDisableBlocking`. Devuelve hasta cuándo queda desactivado. */
export async function temporaryDisableBlocking(
  token: string | null,
  minutes: string,
): Promise<string | null> {
  const outcome = await apiRequest<{ response: { temporaryDisableBlockingTill: string } }>(
    'settings/temporaryDisableBlocking',
    { token, body: { minutes } },
  )
  return outcome.kind === 'ok' ? outcome.data.response.temporaryDisableBlockingTill : null
}

/** Los trece elementos del backup, en el orden y con las etiquetas de upstream
 *  (index.html:6291-6385). `logs` es el único que NO viene marcado. */
export const ELEMENTOS_BACKUP = [
  { key: 'authConfig', label: 'Authentication Config File (auth.config)' },
  { key: 'clusterConfig', label: 'Cluster Config File (cluster.config)' },
  { key: 'webServiceSettings', label: 'Web Service Config And Certificate File (webservice.config, *.pfx & *.p12)' },
  { key: 'dnsSettings', label: 'DNS Config And Certificate File (dns.config, *.pfx & *.p12)' },
  { key: 'logSettings', label: 'Log Config File (log.config)' },
  { key: 'zones', label: 'DNS Zone Files (*.zone)' },
  { key: 'allowedZones', label: 'Allowed Zones File (allowed.config)' },
  { key: 'blockedZones', label: 'Blocked Zones File (blocked.config)' },
  { key: 'blockLists', label: 'Block List Config And Cache Files (blocklist.config)' },
  { key: 'apps', label: 'DNS Apps' },
  { key: 'scopes', label: 'DHCP Scope Files (*.scope)' },
  { key: 'stats', label: 'Dashboard Stats Files (*.stat, *.dstat)' },
  { key: 'logs', label: 'Log Files (*.log)' },
] as const

export type ElementoBackup = (typeof ELEMENTOS_BACKUP)[number]['key']

/** Estado inicial de los dos modales: todo marcado menos los logs
 *  (`resetBackupSettingsModal`, main.js:3049; `resetRestoreSettingsModal`, 3116). */
export function seleccionInicialBackup(): Record<string, boolean> {
  return Object.fromEntries(ELEMENTOS_BACKUP.map((e) => [e.key, e.key !== 'logs']))
}

export function parametrosBackup(
  seleccion: Record<string, boolean>,
  node = '',
): Record<string, string> {
  const params: Record<string, string> = {}
  for (const e of ELEMENTOS_BACKUP) params[e.key] = String(seleccion[e.key] === true)
  params.node = node
  return params
}

/*
`settings/restore` es el ÚNICO endpoint de la consola que manda un fichero, y va
como `multipart/form-data` con el resto de opciones en la query (main.js:3170).
`apiRequest` sólo sabe mandar cuerpos urlencoded, así que aquí se hace el `fetch`
a mano repitiendo su contrato. La solución buena es una opción `body: FormData`
en `src/api/client.ts`, que esta fase no puede tocar; queda anotado.
*/
export async function restoreSettings(
  token: string | null,
  fichero: File,
  seleccion: Record<string, boolean>,
  deleteExistingFiles: boolean,
  node = '',
): Promise<ApiOutcome<{ response: DnsSettings }>> {
  const query = new URLSearchParams(parametrosBackup(seleccion, node))
  query.set('deleteExistingFiles', String(deleteExistingFiles))

  const cuerpo = new FormData()
  cuerpo.append('fileBackupZip', fichero)

  let payload: { status?: string; errorMessage?: string }
  try {
    const res = await fetch(`api/settings/restore?${query.toString()}`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: cuerpo,
    })
    payload = (await res.json()) as { status?: string; errorMessage?: string }
  } catch {
    return { kind: 'error', message: 'Unable to reach the DNS server.' }
  }

  switch (payload.status) {
    case 'ok':
      return { kind: 'ok', data: payload as { response: DnsSettings } }
    case 'invalid-token':
      return { kind: 'invalid-token' }
    case '2fa-required':
      return { kind: 'two-factor-required' }
    default:
      return { kind: 'error', message: payload.errorMessage ?? 'Unknown error.' }
  }
}

/** `cache/flush` (other-zones.js:20). Vive aquí de prestado: ver cabecera. */
export async function flushCache(token: string | null, node = ''): Promise<boolean> {
  const outcome = await apiRequest('cache/flush', { token, body: { node } })
  return outcome.kind === 'ok'
}
