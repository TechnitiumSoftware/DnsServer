import type { DnsSettings } from '../../api/settings'

/*
The REAL `settings/get` response of a freshly installed v15.4 instance (the one
in `dev/`, served at 127.0.0.1:5381). It is copied as it stands, absent keys
included: `temporaryDisableBlockingTill`, `blockListNextUpdatedOn` and
`clusterNodes` do NOT come when they are null, and that is exactly the case that
has to be drawn correctly ("Not Set", "Not Scheduled").
*/
export const SETTINGS: DnsSettings = {
  "version": "15.4",
  "uptimestamp": "2026-08-25T13:07:31.1734662Z",
  "clusterInitialized": false,
  "dnsServerDomain": "ref.technitium-ui.test",
  "dnsServerLocalEndPoints": [
    "0.0.0.0:53",
    "[::]:53"
  ],
  "dnsServerIPv4SourceAddresses": [
    "0.0.0.0"
  ],
  "dnsServerIPv6SourceAddresses": [
    "::"
  ],
  "defaultRecordTtl": 3600,
  "defaultNsRecordTtl": 14400,
  "defaultSoaRecordTtl": 900,
  "defaultResponsiblePerson": null,
  "useSoaSerialDateScheme": false,
  "minSoaRefresh": 300,
  "minSoaRetry": 300,
  "zoneTransferAllowedNetworks": [],
  "notifyAllowedNetworks": [],
  "dnsServerEnableCheckForUpdate": true,
  "dnsAppsEnableAutomaticUpdate": true,
  "ipv6Mode": "Disabled",
  "preferIPv6": false,
  "enableUdpSocketPool": false,
  "socketPoolExcludedPorts": [
    53443
  ],
  "udpPayloadSize": 1232,
  "dnssecValidation": true,
  "eDnsClientSubnet": false,
  "eDnsClientSubnetIPv4PrefixLength": 24,
  "eDnsClientSubnetIPv6PrefixLength": 56,
  "eDnsClientSubnetIpv4Override": null,
  "eDnsClientSubnetIpv6Override": null,
  "qpmPrefixLimitsIPv4": [
    {
      "prefix": 32,
      "udpLimit": 600,
      "tcpLimit": 600
    },
    {
      "prefix": 24,
      "udpLimit": 6000,
      "tcpLimit": 6000
    }
  ],
  "qpmPrefixLimitsIPv6": [
    {
      "prefix": 128,
      "udpLimit": 600,
      "tcpLimit": 600
    },
    {
      "prefix": 64,
      "udpLimit": 1200,
      "tcpLimit": 1200
    },
    {
      "prefix": 56,
      "udpLimit": 6000,
      "tcpLimit": 6000
    }
  ],
  "qpmLimitSampleMinutes": 5,
  "qpmLimitUdpTruncationPercentage": 50,
  "qpmLimitBypassList": [],
  "clientTimeout": 2000,
  "tcpSendTimeout": 10000,
  "tcpReceiveTimeout": 10000,
  "quicIdleTimeout": 60000,
  "quicMaxInboundStreams": 100,
  "listenBacklog": 100,
  "udpSendBufferSizeKB": 2048,
  "udpReceiveBufferSizeKB": 2048,
  "maxConcurrentResolutionsPerCore": 100,
  "webServiceLocalAddresses": [
    "[::]"
  ],
  "webServiceHttpPort": 5380,
  "webServiceEnableHttpUnixSocket": false,
  "webServiceHttpUnixSocket": null,
  "webServiceEnableTlsUnixSocket": false,
  "webServiceTlsUnixSocket": null,
  "webServiceEnableTls": false,
  "webServiceEnableHttp3": false,
  "webServiceHttpToTlsRedirect": false,
  "webServiceUseSelfSignedTlsCertificate": false,
  "webServiceTlsPort": 53443,
  "webServiceReverseProxyAddresses": [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "!2000::/3",
    "::/0"
  ],
  "webServiceRealIpHeader": "X-Real-IP",
  "webServiceCspFrameAncestorsHeader": "'none'",
  "webServiceTlsCertificatePath": null,
  "webServiceTlsCertificatePassword": null,
  "enableEDnsClientSubnetSourceAddress": false,
  "enableDnsOverUdpProxy": false,
  "enableDnsOverTcpProxy": false,
  "enableDnsOverHttp": false,
  "enableDnsOverHttpUnixSocket": false,
  "enableDnsOverHttpsUnixSocket": false,
  "enableDnsOverTls": false,
  "enableDnsOverHttps": false,
  "enableDnsOverHttp3": false,
  "enableDnsOverQuic": false,
  "enableDnsOverHttpHelpRedirect": true,
  "dnsOverUdpProxyPort": 538,
  "dnsOverTcpProxyPort": 538,
  "dnsOverHttpPort": 80,
  "dnsOverHttpUnixSocket": null,
  "dnsOverHttpsUnixSocket": null,
  "dnsOverTlsPort": 853,
  "dnsOverHttpsPort": 443,
  "dnsOverQuicPort": 853,
  "dnsReverseProxyNetworkACL": [],
  "dnsOverHttpRealIpHeader": "X-Real-IP",
  "dnsTlsCertificatePath": null,
  "dnsTlsCertificatePassword": null,
  "tsigKeys": [],
  "recursion": "AllowOnlyForPrivateNetworks",
  "recursionNetworkACL": [],
  "randomizeName": false,
  "qnameMinimization": true,
  "locallyServedDnsZones": true,
  "resolverRetries": 2,
  "resolverTimeout": 1500,
  "resolverConcurrency": 2,
  "resolverMaxStackCount": 16,
  "saveCache": true,
  "serveStale": true,
  "serveStaleTtl": 259200,
  "serveStaleAnswerTtl": 30,
  "serveStaleResetTtl": 30,
  "serveStaleMaxWaitTime": 1800,
  "cacheMaximumEntries": 10000,
  "cacheMinimumRecordTtl": 10,
  "cacheMaximumRecordTtl": 604800,
  "cacheNegativeRecordTtl": 300,
  "cacheFailureRecordTtl": 10,
  "cachePrefetchEligibility": 2,
  "cachePrefetchTrigger": 9,
  "cachePrefetchSampleIntervalInMinutes": 5,
  "cachePrefetchSampleEligibilityHitsPerHour": 30,
  "enableBlocking": true,
  "allowTxtBlockingReport": true,
  "blockingBypassList": [],
  "blockingType": "NxDomain",
  "blockingAnswerTtl": 30,
  "customBlockingAddresses": [],
  "blockListUrls": null,
  "blockListUpdateIntervalHours": 24,
  "proxy": null,
  "forwarders": [
    "1.1.1.1",
    "8.8.8.8"
  ],
  "forwarderProtocol": "Udp",
  "concurrentForwarding": true,
  "forwarderRetries": 3,
  "forwarderTimeout": 2000,
  "forwarderConcurrency": 2,
  "enableLogging": true,
  "loggingType": "File",
  "ignoreResolverLogs": false,
  "logQueries": false,
  "noStackTrace": false,
  "useLocalTime": false,
  "logFolder": "/var/log/technitium/dns",
  "maxLogFileDays": 365,
  "enableInMemoryStats": false,
  "maxStatFileDays": 365
}
