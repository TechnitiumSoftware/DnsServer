import { apiRequest, type ApiOutcome } from './client'

/*
The `settings` family. Six endpoints come from the old console:

  settings/get                      main.js:891  (refreshDnsSettings)
  settings/set                      main.js:2189 (saveDnsSettings, POST)
  settings/forceUpdateBlockLists    main.js:2346
  settings/temporaryDisableBlocking main.js:2373
  settings/backup                   main.js:3067 (descarga, token de un solo uso)
  settings/restore                  main.js:3137 (POST multipart)

The screen's seventh control, "Flush Cache", is NOT of this family: it calls
`cache/flush` (other-zones.js:20). It is declared here because the Settings
action bar is its only consumer until phase 5 arrives with `src/api/cache.ts`;
once that exists, it moves there.

Three things checked against a v15.4 instance that are NOT deducible from the code:

  1. `settings/get` OMITS the null keys instead of sending them as null. On a
     fresh install neither `temporaryDisableBlockingTill`, nor
     `blockListNextUpdatedOn`, nor `clusterNodes` appear. That is why they are
     optional here and `loadDnsSettings` compares them with `== null`: absent and
     null count the same. `blockListUrls`, `proxy`, `defaultResponsiblePerson`
     and the four certificate paths, on the other hand, do arrive explicitly as
     `null`.
  2. `proxy` is a nested object (`type`/`address`/`port`/`username`/`password`/
     `bypass`) when reading, but when saving it is sent FLAT: `proxyType`,
     `proxyAddress`… And when the type is `none` NO other proxy field is sent at
     all (main.js:2122-2123): the bypass list is lost on purpose.
  3. `settings/set` returns the complete settings, just like `get`, and upstream
     uses them to redraw the form. That is how the server's sanitising shows.
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

  // General — local parameters
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

  // General — software update
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

  // General — queries-per-minute limit
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

/** `settings/get`. `node` exists for cluster mode; with a single instance
 *  upstream sends the empty string and the server answers with its own settings. */
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

/** `settings/set`. Goes by POST with the body urlencoded, just like upstream,
 *  and returns the settings already sanitised by the server so the form can be
 *  redrawn. The whole `ApiOutcome` is returned because the screen needs the
 *  server's `errorMessage` for the `Error!` alert. */
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

/** `settings/forceUpdateBlockLists`. No parameters: forces the download now. */
export async function forceUpdateBlockLists(token: string | null): Promise<boolean> {
  const outcome = await apiRequest('settings/forceUpdateBlockLists', { token })
  return outcome.kind === 'ok'
}

/** `settings/temporaryDisableBlocking`. Returns until when it stays disabled. */
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

/** The thirteen items of the backup, in upstream's order and with its labels
 *  (index.html:6291-6385). `logs` is the only one that does NOT come checked. */
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

/** Initial state of the two modals: everything checked except the logs
 *  (`resetBackupSettingsModal`, main.js:3049; `resetRestoreSettingsModal`, 3116). */
export function seleccionInicialBackup(): Record<string, boolean> {
  return Object.fromEntries(ELEMENTOS_BACKUP.map((e) => [e.key, e.key !== 'logs']))
}

export function parametrosBackup(
  selection: Record<string, boolean>,
  node = '',
): Record<string, string> {
  const params: Record<string, string> = {}
  for (const e of ELEMENTOS_BACKUP) params[e.key] = String(selection[e.key] === true)
  params.node = node
  return params
}

/*
`settings/restore` sends the file by multipart and the rest of the options in the
QUERY, not in the body (main.js:3170). That is honoured to the letter: the path
comes with the query already built and `apiRequest` only adds the FormData with
the zip.
*/
export async function restoreSettings(
  token: string | null,
  fichero: File,
  selection: Record<string, boolean>,
  deleteExistingFiles: boolean,
  node = '',
): Promise<ApiOutcome<{ response: DnsSettings }>> {
  const query = new URLSearchParams(parametrosBackup(selection, node))
  query.set('deleteExistingFiles', String(deleteExistingFiles))

  return apiRequest<{ response: DnsSettings }>(`settings/restore?${query.toString()}`, {
    token,
    method: 'POST',
    file: { field: 'fileBackupZip', archivo: fichero },
  })
}

/** `cache/flush` (other-zones.js:20). It lives here on loan: see the header. */
export async function flushCache(token: string | null, node = ''): Promise<boolean> {
  const outcome = await apiRequest('cache/flush', { token, body: { node } })
  return outcome.kind === 'ok'
}

/*
`settings/getTsigKeyNames` belongs to this family but **it is consumed by the
Zones screen** (zone.js), to pick the TSIG key in a zone's options and in a
secondary's SOA. It lives here by family, not by screen.
*/
export async function getTsigKeyNames(token: string | null, node = ''): Promise<string[]> {
  const outcome = await apiRequest<{ response: { tsigKeyNames: string[] } }>(
    'settings/getTsigKeyNames',
    { token, body: { node } },
  )
  return outcome.kind === 'ok' ? (outcome.data.response.tsigKeyNames ?? []) : []
}
