import { describe, expect, it, vi, afterEach } from 'vitest'
import { resolve, prepararServidor, TYPES, PROTOCOLS } from './dnsclient'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())

describe('dnsClient', () => {
  it('it offers the 28 types and the 5 protocols of upstream', () => {
    expect(TYPES).toHaveLength(28)
    expect(TYPES[0]).toBe('A')
    expect(TYPES).toContain('AXFR')
    expect(PROTOCOLS).toEqual(['UDP','TCP','TLS','HTTPS','QUIC'])
  })

  it('it sends the parameters under the upstream names', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await resolve('t', { server: 'this-server', domain: 'casa.test', type: 'A', protocol: 'UDP', dnssec: true })
    expect(spy.mock.calls[0][0]).toBe('dnsClient/resolve')
    expect(spy.mock.calls[0][1]?.body).toEqual({
      server: 'this-server', domain: 'casa.test', type: 'A',
      protocol: 'UDP', dnssec: 'true', eDnsClientSubnet: '',
    })
  })

  it('it only adds import=true when importing is asked for', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await resolve('t', { server: 's', domain: 'd', type: 'A', protocol: 'UDP', dnssec: false })
    expect(spy.mock.calls[0][1]?.body?.import).toBeUndefined()
    spy.mockClear()
    await resolve('t', { server: 's', domain: 'd', type: 'A', protocol: 'UDP', dnssec: false, runImport: true })
    expect(spy.mock.calls[0][1]?.body?.import).toBe('true')
  })
})

describe('prepararServidor', () => {
  it('it extracts what sits between braces: that is what gets sent', () => {
    expect(prepararServidor('This Server {this-server}', 'UDP').server).toBe('this-server')
    expect(prepararServidor('Cloudflare {1.1.1.1} (DNS-over-TLS)', 'TLS').server).toBe('1.1.1.1')
  })

  it('with no braces, it sends the text as it is', () => {
    expect(prepararServidor('8.8.8.8', 'UDP').server).toBe('8.8.8.8')
  })

  it('it forces UDP for recursive-resolver and system-dns', () => {
    expect(prepararServidor('Recursive Resolver {recursive-resolver}', 'TLS').protocol).toBe('UDP')
    expect(prepararServidor('System DNS {system-dns}', 'HTTPS').protocol).toBe('UDP')
  })

  it('it honours the chosen protocol for any other server', () => {
    expect(prepararServidor('{1.1.1.1}', 'TLS').protocol).toBe('TLS')
  })

  it('empty braces are an empty server, even though the field has text', () => {
    expect(prepararServidor('Servidor {}', 'UDP').server).toBe('')
  })
})
