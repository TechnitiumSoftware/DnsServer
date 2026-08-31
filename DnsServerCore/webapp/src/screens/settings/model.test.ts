import { describe, expect, it } from 'vitest'
import { AJUSTES } from './ajustes.fixture'
import { construirCuerpo, formularioDesdeAjustes, habilitado, limpiarLista, listaATexto } from './model'

const base = () => formularioDesdeAjustes(AJUSTES)

function cuerpo(parcial: Partial<ReturnType<typeof base>> = {}) {
  const r = construirCuerpo({ ...base(), ...parcial })
  expect(r.error).toBeUndefined()
  return r.body!
}

describe('listaATexto / limpiarLista', () => {
  it('una entrada por línea, con CRLF, igual que getArrayAsString', () => {
    expect(listaATexto(['a', 'b'])).toBe('a\nb\n')
    expect(listaATexto(null)).toBe('')
    expect(listaATexto([])).toBe('')
  })

  it('cleanTextList colapsa comas y quita las de los extremos', () => {
    expect(limpiarLista('\na\n\n\nb\n')).toBe('a,b')
    expect(limpiarLista('\n\n')).toBe('')
    expect(limpiarLista('a')).toBe('a')
  })
})

describe('formularioDesdeAjustes', () => {
  it('vuelca la respuesta real de v15.4 sin perder nada', () => {
    const f = base()
    expect(f.dnsServerDomain).toBe('ref.technitium-ui.test')
    expect(f.dnsServerLocalEndPoints).toBe('0.0.0.0:53\n[::]:53\n')
    expect(f.qpmPrefixLimitsIPv4).toHaveLength(2)
    expect(f.qpmPrefixLimitsIPv4[0]).toEqual({ prefix: '32', udpLimit: '600', tcpLimit: '600' })
    expect(f.forwarders).toBe('1.1.1.1\n8.8.8.8\n')
    expect(f.recursion).toBe('AllowOnlyForPrivateNetworks')
  })

  it('los nulos se pintan como cadena vacía, no como «null»', () => {
    const f = base()
    expect(f.defaultResponsiblePerson).toBe('')
    expect(f.blockListUrls).toBe('')
    expect(f.webServiceTlsCertificatePath).toBe('')
  })

  it('sin proxy, el tipo es None y los campos quedan vacíos', () => {
    const f = base()
    expect(f.proxyType).toBe('None')
    expect(f.proxyPort).toBe('')
    expect(f.proxyBypassList).toBe('')
  })

  it('el tipo de proxy se normaliza sin importar mayúsculas', () => {
    const f = formularioDesdeAjustes({
      ...AJUSTES,
      proxy: { type: 'SOCKS5', address: 'p', port: 1080, username: '', password: '', bypass: [] },
    })
    expect(f.proxyType).toBe('Socks5')
    expect(f.proxyPort).toBe('1080')
  })

  it('el campo de minutos del bloqueo temporal se vacía en cada carga', () => {
    expect(base().temporaryDisableBlockingMinutes).toBe('')
  })
})

describe('habilitado', () => {
  it('sin bloqueo, se apaga toda la sub-pestaña Blocking', () => {
    const en = habilitado({ ...base(), enableBlocking: false })
    expect(en.blocking).toBe(false)
    expect(en.customBlockingAddresses).toBe(false)
    expect(en.actualizarListasAhora).toBe(false)
  })

  it('«Update Now» sigue apagado con bloqueo activo pero sin listas', () => {
    expect(habilitado({ ...base(), enableBlocking: true, blockListUrls: '' }).actualizarListasAhora).toBe(false)
    expect(habilitado({ ...base(), enableBlocking: true, blockListUrls: 'http://x\n' }).actualizarListasAhora).toBe(true)
  })

  it('la ACL de recursión sólo se edita con la cuarta opción', () => {
    expect(habilitado({ ...base(), recursion: 'Allow' }).recursionNetworkACL).toBe(false)
    expect(habilitado({ ...base(), recursion: 'UseSpecifiedNetworkACL' }).recursionNetworkACL).toBe(true)
  })

  it('el certificado del Web Service se habilita con HTTPS o con su UDS', () => {
    expect(habilitado({ ...base(), webServiceEnableTls: false, webServiceEnableTlsUnixSocket: false }).webServiceTlsCert).toBe(false)
    expect(habilitado({ ...base(), webServiceEnableTls: false, webServiceEnableTlsUnixSocket: true }).webServiceTlsCert).toBe(true)
  })

  it('la ACL del proxy inverso de DNS se habilita con cualquiera de los cinco', () => {
    const f = base()
    expect(habilitado(f).dnsReverseProxyNetworkACL).toBe(false)
    expect(habilitado({ ...f, enableDnsOverHttp: true }).dnsReverseProxyNetworkACL).toBe(true)
  })

  it('sin registro, se apagan sus cuatro opciones y la carpeta', () => {
    expect(habilitado({ ...base(), loggingType: 'None' }).logging).toBe(false)
    expect(habilitado({ ...base(), loggingType: 'FileAndConsole' }).logging).toBe(true)
  })
})

describe('construirCuerpo — orden de validación de saveDnsSettings', () => {
  const casos: [string, Record<string, unknown>, string][] = [
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

  it.each(casos)('%s vacío da el aviso literal de upstream', (_n, parcial, texto) => {
    const r = construirCuerpo({ ...base(), ...parcial } as ReturnType<typeof base>)
    expect(r.error?.title).toBe('Missing!')
    expect(r.error?.text).toBe(texto)
    expect(r.body).toBeUndefined()
  })

  it('el dominio se comprueba ANTES que el prefijo ECS', () => {
    const r = construirCuerpo({
      ...base(),
      dnsServerDomain: '',
      eDnsClientSubnetIPv4PrefixLength: '',
    })
    expect(r.error?.text).toBe('Please enter server domain name.')
  })

  it('el prefijo ECS se comprueba ANTES que la tabla QPM', () => {
    const r = construirCuerpo({
      ...base(),
      eDnsClientSubnetIPv4PrefixLength: '',
      qpmPrefixLimitsIPv4: [{ prefix: '', udpLimit: '', tcpLimit: '' }],
    })
    expect(r.error?.text).toBe('Please enter EDNS Client Subnet IPv4 prefix length.')
  })

  it('una celda vacía en la tabla QPM da el aviso de serializeTableData', () => {
    const r = construirCuerpo({
      ...base(),
      qpmPrefixLimitsIPv4: [{ prefix: '32', udpLimit: '', tcpLimit: '600' }],
    })
    expect(r.error).toEqual({
      title: 'Missing!',
      text: 'Please enter a valid value in the text field in focus.',
      tab: 'General',
      campo: 'qpmPrefixLimitsIPv4',
    })
  })

  it('un «|» en una celda da el aviso de carácter inválido', () => {
    const r = construirCuerpo({
      ...base(),
      tsigKeys: [{ keyName: 'a|b', sharedSecret: '', algorithmName: 'hmac-sha256' }],
    })
    expect(r.error).toEqual({
      title: 'Invalid Character!',
      text: "Please edit the value in the text field in focus to remove '|' character.",
      tab: 'TSIG',
      campo: 'tsigKeys',
    })
  })

  it('el secreto TSIG vacío SÍ se admite: es el único data-optional', () => {
    const b = cuerpo({ tsigKeys: [{ keyName: 'k1', sharedSecret: '', algorithmName: 'hmac-sha256' }] })
    expect(b.tsigKeys).toBe('k1||hmac-sha256')
  })

  it('con proxy distinto de None, faltan dirección y puerto en ese orden', () => {
    expect(construirCuerpo({ ...base(), proxyType: 'Http' }).error?.text).toBe(
      'Please enter proxy server address.',
    )
    expect(construirCuerpo({ ...base(), proxyType: 'Http', proxyAddress: 'p' }).error?.text).toBe(
      'Please enter proxy server port.',
    )
  })

  it('la sub-pestaña del error acompaña al aviso para poder saltar a ella', () => {
    expect(construirCuerpo({ ...base(), resolverRetries: '' }).error?.tab).toBe('Recursion')
    expect(construirCuerpo({ ...base(), cacheMaximumEntries: '' }).error?.tab).toBe('Cache')
    expect(construirCuerpo({ ...base(), dnsOverTlsPort: '' }).error?.tab).toBe('Optional Protocols')
    expect(construirCuerpo({ ...base(), forwarderRetries: '' }).error?.tab).toBe('Proxy & Forwarders')
  })
})

describe('construirCuerpo — cuerpo de settings/set', () => {
  it('las listas vacías viajan como la cadena «false»', () => {
    const b = cuerpo()
    expect(b.zoneTransferAllowedNetworks).toBe('false')
    expect(b.notifyAllowedNetworks).toBe('false')
    expect(b.blockListUrls).toBe('false')
    expect(b.recursionNetworkACL).toBe('false')
    expect(b.qpmLimitBypassList).toBe('false')
  })

  it('los End Points vacíos caen a su valor por defecto, no a «false»', () => {
    expect(cuerpo({ dnsServerLocalEndPoints: '' }).dnsServerLocalEndPoints).toBe('0.0.0.0:53,[::]:53')
    expect(cuerpo({ webServiceLocalAddresses: '' }).webServiceLocalAddresses).toBe('0.0.0.0,[::]')
    expect(cuerpo({ webServiceHttpPort: '' }).webServiceHttpPort).toBe('5380')
  })

  it('los textareas se mandan con comas, una entrada por coma', () => {
    const b = cuerpo({ forwarders: '1.1.1.1\n8.8.8.8\n' })
    expect(b.forwarders).toBe('1.1.1.1,8.8.8.8')
  })

  it('las tablas se serializan con «|» entre TODAS las celdas', () => {
    const b = cuerpo()
    expect(b.qpmPrefixLimitsIPv4).toBe('32|600|600|24|6000|6000')
  })

  it('las tablas vacías viajan como «false»', () => {
    const b = cuerpo({ qpmPrefixLimitsIPv4: [], qpmPrefixLimitsIPv6: [], tsigKeys: [] })
    expect(b.qpmPrefixLimitsIPv4).toBe('false')
    expect(b.tsigKeys).toBe('false')
  })

  it('con «No Proxy» NO se manda ningún otro campo de proxy', () => {
    const b = cuerpo()
    expect(b.proxyType).toBe('none')
    expect(b.proxyAddress).toBeUndefined()
    expect(b.proxyBypass).toBeUndefined()
  })

  it('con proxy configurado, el bypass vacío es cadena vacía y no «false»', () => {
    const b = cuerpo({ proxyType: 'Socks5', proxyAddress: 'p', proxyPort: '1080' })
    expect(b.proxyType).toBe('socks5')
    expect(b.proxyBypass).toBe('')
  })

  it('los booleanos viajan como «true»/«false» en minúsculas', () => {
    const b = cuerpo()
    expect(b.dnssecValidation).toBe('true')
    expect(b.enableUdpSocketPool).toBe('false')
  })

  it('manda los campos de LAS NUEVE sub-pestañas, no sólo la visible', () => {
    const b = cuerpo()
    for (const clave of [
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
      expect(b[clave], clave).toBeDefined()
    }
  })

  it('devuelve el saneado que upstream reescribe en los textareas', () => {
    const r = construirCuerpo({ ...base(), blockingBypassList: '10.0.0.1\n\n10.0.0.2\n' })
    // Blocking adds a trailing newline; the forwarders do not. Upstream's asymmetry.
    expect(r.saneado?.blockingBypassList).toBe('10.0.0.1\n10.0.0.2\n')
    expect(r.saneado?.forwarders).toBe('1.1.1.1\n8.8.8.8')
  })
})
