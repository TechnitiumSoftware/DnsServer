import { describe, expect, it } from 'vitest'
import { SETTINGS } from './settings.fixture'
import { buildBody, formularioDesdeAjustes, enabled, cleanList, listToText } from './model'

const base = () => formularioDesdeAjustes(SETTINGS)

function body(partial: Partial<ReturnType<typeof base>> = {}) {
  const r = buildBody({ ...base(), ...partial })
  expect(r.error).toBeUndefined()
  return r.body!
}

describe('listaATexto / limpiarLista', () => {
  it('one entry per line, with CRLF, just like getArrayAsString', () => {
    expect(listToText(['a', 'b'])).toBe('a\nb\n')
    expect(listToText(null)).toBe('')
    expect(listToText([])).toBe('')
  })

  it('cleanTextList collapses commas and strips the ones at the ends', () => {
    expect(cleanList('\na\n\n\nb\n')).toBe('a,b')
    expect(cleanList('\n\n')).toBe('')
    expect(cleanList('a')).toBe('a')
  })
})

describe('formularioDesdeAjustes', () => {
  it('it pours in the real v15.4 response without losing anything', () => {
    const f = base()
    expect(f.dnsServerDomain).toBe('ref.technitium-ui.test')
    expect(f.dnsServerLocalEndPoints).toBe('0.0.0.0:53\n[::]:53\n')
    expect(f.qpmPrefixLimitsIPv4).toHaveLength(2)
    expect(f.qpmPrefixLimitsIPv4[0]).toEqual({ prefix: '32', udpLimit: '600', tcpLimit: '600' })
    expect(f.forwarders).toBe('1.1.1.1\n8.8.8.8\n')
    expect(f.recursion).toBe('AllowOnlyForPrivateNetworks')
  })

  it('the nulls are drawn as an empty string, not as \"null\"', () => {
    const f = base()
    expect(f.defaultResponsiblePerson).toBe('')
    expect(f.blockListUrls).toBe('')
    expect(f.webServiceTlsCertificatePath).toBe('')
  })

  it('with no proxy, the type is None and the fields are left empty', () => {
    const f = base()
    expect(f.proxyType).toBe('None')
    expect(f.proxyPort).toBe('')
    expect(f.proxyBypassList).toBe('')
  })

  it('the proxy type is normalised regardless of case', () => {
    const f = formularioDesdeAjustes({
      ...SETTINGS,
      proxy: { type: 'SOCKS5', address: 'p', port: 1080, username: '', password: '', bypass: [] },
    })
    expect(f.proxyType).toBe('Socks5')
    expect(f.proxyPort).toBe('1080')
  })

  it('the minutes field of the temporary blocking empties on every load', () => {
    expect(base().temporaryDisableBlockingMinutes).toBe('')
  })
})

describe('enabled', () => {
  it('with no blocking, the whole Blocking sub-tab goes off', () => {
    const en = enabled({ ...base(), enableBlocking: false })
    expect(en.blocking).toBe(false)
    expect(en.customBlockingAddresses).toBe(false)
    expect(en.updateListsNow).toBe(false)
  })

  it('\"Update Now\" stays off with blocking on but no lists', () => {
    expect(enabled({ ...base(), enableBlocking: true, blockListUrls: '' }).updateListsNow).toBe(false)
    expect(enabled({ ...base(), enableBlocking: true, blockListUrls: 'http://x\n' }).updateListsNow).toBe(true)
  })

  it('the recursion ACL is only edited with the fourth option', () => {
    expect(enabled({ ...base(), recursion: 'Allow' }).recursionNetworkACL).toBe(false)
    expect(enabled({ ...base(), recursion: 'UseSpecifiedNetworkACL' }).recursionNetworkACL).toBe(true)
  })

  it('the Web Service certificate is enabled by HTTPS or by its UDS', () => {
    expect(enabled({ ...base(), webServiceEnableTls: false, webServiceEnableTlsUnixSocket: false }).webServiceTlsCert).toBe(false)
    expect(enabled({ ...base(), webServiceEnableTls: false, webServiceEnableTlsUnixSocket: true }).webServiceTlsCert).toBe(true)
  })

  it('the reverse DNS proxy ACL is enabled by any of the five', () => {
    const f = base()
    expect(enabled(f).dnsReverseProxyNetworkACL).toBe(false)
    expect(enabled({ ...f, enableDnsOverHttp: true }).dnsReverseProxyNetworkACL).toBe(true)
  })

  it('with no logging, its four options and the folder go off', () => {
    expect(enabled({ ...base(), loggingType: 'None' }).logging).toBe(false)
    expect(enabled({ ...base(), loggingType: 'FileAndConsole' }).logging).toBe(true)
  })
})

describe('construirCuerpo — validation order of saveDnsSettings', () => {
  const cases: [string, Record<string, unknown>, string][] = [
    ['dnsServerDomain', { dnsServerDomain: '' }, 'Please enter server domain name.'],
    ['ECS IPv4', { eDnsClientSubnetIPv4PrefixLength: '' }, 'Please enter EDNS Client Subnet IPv4 prefix length.'],
    ['ECS IPv6', { eDnsClientSubnetIPv6PrefixLength: '' }, 'Please enter EDNS Client Subnet IPv6 prefix length.'],
    ['QPM sample', { qpmLimitSampleMinutes: '' }, 'Please enter Queries Per Minute (QPM) sample value.'],
    ['QPM truncation', { qpmLimitUdpTruncationPercentage: '' }, 'Please enter Queries Per Minute (QPM) limit UDP truncation percentage value.'],
    ['clientTimeout', { clientTimeout: '' }, 'Please enter a value for Client Timeout.'],
    ['tcpSendTimeout', { tcpSendTimeout: '' }, 'Please enter a value for TCP Send Timeout.'],
    ['tcpReceiveTimeout', { tcpReceiveTimeout: '' }, 'Please enter a value for TCP Receive Timeout.'],
    ['quicIdleTimeout', { quicIdleTimeout: '' }, 'Please enter a value for QUIC Idle Timeout.'],
    ['quicMaxInboundStreams', { quicMaxInboundStreams: '' }, 'Please enter a value for QUIC Max Inbound Streams.'],
    ['listenBacklog', { listenBacklog: '' }, 'Please enter a value for Listen Backlog.'],
    ['udpSendBufferSizeKB', { udpSendBufferSizeKB: '' }, 'Please enter a value for UDP Send Buffer Size.'],
    ['udpReceiveBufferSizeKB', { udpReceiveBufferSizeKB: '' }, 'Please enter a value for UDP Receive Buffer Size.'],
    ['maxConcurrentResolutionsPerCore', { maxConcurrentResolutionsPerCore: '' }, 'Please enter a value for Max Concurrent Resolutions.'],
    ['dnsOverUdpProxyPort', { dnsOverUdpProxyPort: '' }, 'Please enter a value for DNS-over-UDP-PROXY Port.'],
    ['dnsOverTcpProxyPort', { dnsOverTcpProxyPort: '' }, 'Please enter a value for DNS-over-TCP-PROXY Port.'],
    ['dnsOverHttpPort', { dnsOverHttpPort: '' }, 'Please enter a value for DNS-over-HTTP Port.'],
    ['dnsOverTlsPort', { dnsOverTlsPort: '' }, 'Please enter a value for DNS-over-TLS Port.'],
    ['dnsOverHttpsPort', { dnsOverHttpsPort: '' }, 'Please enter a value for DNS-over-HTTPS Port.'],
    ['dnsOverQuicPort', { dnsOverQuicPort: '' }, 'Please enter a value for DNS-over-QUIC Port.'],
    ['resolverRetries', { resolverRetries: '' }, 'Please enter a value for Resolver Retries.'],
    ['resolverTimeout', { resolverTimeout: '' }, 'Please enter a value for Resolver Timeout.'],
    ['resolverConcurrency', { resolverConcurrency: '' }, 'Please enter a value for Resolver Concurrency.'],
    ['resolverMaxStackCount', { resolverMaxStackCount: '' }, 'Please enter a value for Resolver Max Stack Count.'],
    ['cacheMaximumEntries', { cacheMaximumEntries: '' }, 'Please enter cache maximum entries value.'],
    ['cacheMinimumRecordTtl', { cacheMinimumRecordTtl: '' }, 'Please enter cache minimum record TTL value.'],
    ['cacheMaximumRecordTtl', { cacheMaximumRecordTtl: '' }, 'Please enter cache maximum record TTL value.'],
    ['cacheNegativeRecordTtl', { cacheNegativeRecordTtl: '' }, 'Please enter cache negative record TTL value.'],
    ['cacheFailureRecordTtl', { cacheFailureRecordTtl: '' }, 'Please enter cache failure record TTL value.'],
    ['cachePrefetchEligibility', { cachePrefetchEligibility: '' }, 'Please enter cache prefetch eligibility value.'],
    ['cachePrefetchTrigger', { cachePrefetchTrigger: '' }, 'Please enter cache prefetch trigger value.'],
    ['cachePrefetchSampleIntervalInMinutes', { cachePrefetchSampleIntervalInMinutes: '' }, 'Please enter cache auto prefetch sample interval value.'],
    ['cachePrefetchSampleEligibilityHitsPerHour', { cachePrefetchSampleEligibilityHitsPerHour: '' }, 'Please enter cache auto prefetch sample eligibility value.'],
    ['forwarderRetries', { forwarderRetries: '' }, 'Please enter a value for Forwarder Retries.'],
    ['forwarderTimeout', { forwarderTimeout: '' }, 'Please enter a value for Forwarder Timeout.'],
    ['forwarderConcurrency', { forwarderConcurrency: '' }, 'Please enter a value for Forwarder Concurrency.'],
  ]

  it.each(cases)('%s vacío da el aviso literal de upstream', (_n, partial, text) => {
    const r = buildBody({ ...base(), ...partial } as ReturnType<typeof base>)
    expect(r.error?.title).toBe('Missing!')
    expect(r.error?.text).toBe(text)
    expect(r.body).toBeUndefined()
  })

  it('the domain is checked BEFORE the ECS prefix', () => {
    const r = buildBody({
      ...base(),
      dnsServerDomain: '',
      eDnsClientSubnetIPv4PrefixLength: '',
    })
    expect(r.error?.text).toBe('Please enter server domain name.')
  })

  it('the ECS prefix is checked BEFORE the QPM table', () => {
    const r = buildBody({
      ...base(),
      eDnsClientSubnetIPv4PrefixLength: '',
      qpmPrefixLimitsIPv4: [{ prefix: '', udpLimit: '', tcpLimit: '' }],
    })
    expect(r.error?.text).toBe('Please enter EDNS Client Subnet IPv4 prefix length.')
  })

  it('an empty cell in the QPM table gives the serializeTableData alert', () => {
    const r = buildBody({
      ...base(),
      qpmPrefixLimitsIPv4: [{ prefix: '32', udpLimit: '', tcpLimit: '600' }],
    })
    expect(r.error).toEqual({
      title: 'Missing!',
      text: 'Please enter a valid value in the text field in focus.',
      tab: 'General',
      field: 'qpmPrefixLimitsIPv4',
    })
  })

  it('a \"|\" in a cell gives the invalid-character alert', () => {
    const r = buildBody({
      ...base(),
      tsigKeys: [{ keyName: 'a|b', sharedSecret: '', algorithmName: 'hmac-sha256' }],
    })
    expect(r.error).toEqual({
      title: 'Invalid Character!',
      text: "Please edit the value in the text field in focus to remove '|' character.",
      tab: 'TSIG',
      field: 'tsigKeys',
    })
  })

  it('an empty TSIG secret IS allowed: it is the only data-optional', () => {
    const b = body({ tsigKeys: [{ keyName: 'k1', sharedSecret: '', algorithmName: 'hmac-sha256' }] })
    expect(b.tsigKeys).toBe('k1||hmac-sha256')
  })

  it('with a proxy other than None, address and port are missing in that order', () => {
    expect(buildBody({ ...base(), proxyType: 'Http' }).error?.text).toBe(
      'Please enter proxy server address.',
    )
    expect(buildBody({ ...base(), proxyType: 'Http', proxyAddress: 'p' }).error?.text).toBe(
      'Please enter proxy server port.',
    )
  })

  it('the sub-tab of the error travels with the alert so it can be jumped to', () => {
    expect(buildBody({ ...base(), resolverRetries: '' }).error?.tab).toBe('Recursion')
    expect(buildBody({ ...base(), cacheMaximumEntries: '' }).error?.tab).toBe('Cache')
    expect(buildBody({ ...base(), dnsOverTlsPort: '' }).error?.tab).toBe('Optional Protocols')
    expect(buildBody({ ...base(), forwarderRetries: '' }).error?.tab).toBe('Proxy & Forwarders')
  })
})

describe('construirCuerpo — body of settings/set', () => {
  it('empty lists travel as the string \"false\"', () => {
    const b = body()
    expect(b.zoneTransferAllowedNetworks).toBe('false')
    expect(b.notifyAllowedNetworks).toBe('false')
    expect(b.blockListUrls).toBe('false')
    expect(b.recursionNetworkACL).toBe('false')
    expect(b.qpmLimitBypassList).toBe('false')
  })

  it('empty End Points fall to their default value, not to \"false\"', () => {
    expect(body({ dnsServerLocalEndPoints: '' }).dnsServerLocalEndPoints).toBe('0.0.0.0:53,[::]:53')
    expect(body({ webServiceLocalAddresses: '' }).webServiceLocalAddresses).toBe('0.0.0.0,[::]')
    expect(body({ webServiceHttpPort: '' }).webServiceHttpPort).toBe('5380')
  })

  it('the textareas are sent with commas, one entry per comma', () => {
    const b = body({ forwarders: '1.1.1.1\n8.8.8.8\n' })
    expect(b.forwarders).toBe('1.1.1.1,8.8.8.8')
  })

  it('the tables serialise with \"|\" between ALL the cells', () => {
    const b = body()
    expect(b.qpmPrefixLimitsIPv4).toBe('32|600|600|24|6000|6000')
  })

  it('empty tables travel as \"false\"', () => {
    const b = body({ qpmPrefixLimitsIPv4: [], qpmPrefixLimitsIPv6: [], tsigKeys: [] })
    expect(b.qpmPrefixLimitsIPv4).toBe('false')
    expect(b.tsigKeys).toBe('false')
  })

  it('with \"No Proxy\" NO other proxy field is sent', () => {
    const b = body()
    expect(b.proxyType).toBe('none')
    expect(b.proxyAddress).toBeUndefined()
    expect(b.proxyBypass).toBeUndefined()
  })

  it('with a proxy configured, an empty bypass is an empty string and not \"false\"', () => {
    const b = body({ proxyType: 'Socks5', proxyAddress: 'p', proxyPort: '1080' })
    expect(b.proxyType).toBe('socks5')
    expect(b.proxyBypass).toBe('')
  })

  it('the booleans travel as lowercase \"true\"/\"false\"', () => {
    const b = body()
    expect(b.dnssecValidation).toBe('true')
    expect(b.enableUdpSocketPool).toBe('false')
  })

  it('it sends the fields of ALL NINE sub-tabs, not just the visible one', () => {
    const b = body()
    for (const key of [
      'dnsServerDomain',
      'webServiceHttpPort',
      'enableDnsOverTls',
      'tsigKeys',
      'recursion',
      'saveCache',
      'enableBlocking',
      'forwarderProtocol',
      'loggingType',
    ]) {
      expect(b[key], key).toBeDefined()
    }
  })

  it('it returns the sanitised text upstream rewrites into the textareas', () => {
    const r = buildBody({ ...base(), blockingBypassList: '10.0.0.1\n\n10.0.0.2\n' })
    // Blocking adds a trailing newline; the forwarders do not. Upstream's asymmetry.
    expect(r.sanitised?.blockingBypassList).toBe('10.0.0.1\n10.0.0.2\n')
    expect(r.sanitised?.forwarders).toBe('1.1.1.1\n8.8.8.8')
  })
})
