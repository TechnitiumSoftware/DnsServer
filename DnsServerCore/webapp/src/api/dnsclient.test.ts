import { describe, expect, it, vi, afterEach } from 'vitest'
import { resolve, prepararServidor, TIPOS, PROTOCOLOS } from './dnsclient'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())

describe('dnsClient', () => {
  it('ofrece los 28 tipos y los 5 protocolos de upstream', () => {
    expect(TIPOS).toHaveLength(28)
    expect(TIPOS[0]).toBe('A')
    expect(TIPOS).toContain('AXFR')
    expect(PROTOCOLOS).toEqual(['UDP','TCP','TLS','HTTPS','QUIC'])
  })

  it('manda los parámetros con los nombres de upstream', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await resolve('t', { server: 'this-server', domain: 'casa.test', type: 'A', protocol: 'UDP', dnssec: true })
    expect(spy.mock.calls[0][0]).toBe('dnsClient/resolve')
    expect(spy.mock.calls[0][1]?.body).toEqual({
      server: 'this-server', domain: 'casa.test', type: 'A',
      protocol: 'UDP', dnssec: 'true', eDnsClientSubnet: '',
    })
  })

  it('sólo añade import=true cuando se pide importar', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await resolve('t', { server: 's', domain: 'd', type: 'A', protocol: 'UDP', dnssec: false })
    expect(spy.mock.calls[0][1]?.body?.import).toBeUndefined()
    spy.mockClear()
    await resolve('t', { server: 's', domain: 'd', type: 'A', protocol: 'UDP', dnssec: false, importar: true })
    expect(spy.mock.calls[0][1]?.body?.import).toBe('true')
  })
})

describe('prepararServidor', () => {
  it('extrae lo que hay entre llaves: eso es lo que se envía', () => {
    expect(prepararServidor('This Server {this-server}', 'UDP').server).toBe('this-server')
    expect(prepararServidor('Cloudflare {1.1.1.1} (DNS-over-TLS)', 'TLS').server).toBe('1.1.1.1')
  })

  it('sin llaves, manda el texto tal cual', () => {
    expect(prepararServidor('8.8.8.8', 'UDP').server).toBe('8.8.8.8')
  })

  it('fuerza UDP para recursive-resolver y system-dns', () => {
    expect(prepararServidor('Recursive Resolver {recursive-resolver}', 'TLS').protocol).toBe('UDP')
    expect(prepararServidor('System DNS {system-dns}', 'HTTPS').protocol).toBe('UDP')
  })

  it('respeta el protocolo elegido para cualquier otro servidor', () => {
    expect(prepararServidor('{1.1.1.1}', 'TLS').protocol).toBe('TLS')
  })

  it('unas llaves vacías son un servidor vacío, aunque el campo tenga texto', () => {
    expect(prepararServidor('Servidor {}', 'UDP').server).toBe('')
  })
})
