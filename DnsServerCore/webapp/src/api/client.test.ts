import { describe, expect, it, vi, beforeEach } from 'vitest'
import { apiRequest } from './client'

function mockFetch(payload: unknown) {
  const spy = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => payload })
  vi.stubGlobal('fetch', spy)
  return spy
}

beforeEach(() => vi.unstubAllGlobals())

describe('apiRequest', () => {
  it('entrega el JSON crudo cuando el status es ok', async () => {
    // user/login y user/session/get devuelven la sesión PLANA, sin envoltorio
    // `response`. Todo lo demás sí la envuelve. Por eso el cliente no
    // desenvuelve: igual que el HTTPRequest de upstream, entrega el JSON tal cual.
    mockFetch({ status: 'ok', token: 'abc', displayName: 'Administrator' })
    const r = await apiRequest('user/login')
    expect(r).toEqual({ kind: 'ok', data: { status: 'ok', token: 'abc', displayName: 'Administrator' } })
  })

  it('entrega también los que vienen envueltos, sin tocarlos', async () => {
    mockFetch({ status: 'ok', response: { zones: [] } })
    const r = await apiRequest('zones/list')
    expect(r).toEqual({ kind: 'ok', data: { status: 'ok', response: { zones: [] } } })
  })

  it('manda el token como cabecera Bearer', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/session/get', { token: 'abc123' })
    expect(spy.mock.calls[0][1].headers.Authorization).toBe('Bearer abc123')
  })

  it('pide las rutas en relativo, sin barra inicial', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/login')
    expect(spy.mock.calls[0][0]).toBe('api/user/login')
  })

  it('pone el cuerpo en la query cuando es GET', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('zones/list', { body: { zone: 'casa.test' } })
    expect(spy.mock.calls[0][0]).toBe('api/zones/list?zone=casa.test')
  })

  it('codifica el cuerpo como formulario cuando es POST', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/login', { method: 'POST', body: { user: 'admin', pass: 'a b&c' } })
    const [url, init] = spy.mock.calls[0]
    expect(url).toBe('api/user/login')
    expect(init.body).toBe('user=admin&pass=a+b%26c')
    expect(init.headers['Content-Type']).toBe('application/x-www-form-urlencoded')
  })

  it('distingue el token invalido', async () => {
    mockFetch({ status: 'invalid-token', errorMessage: 'Invalid token or session expired.' })
    expect(await apiRequest('user/session/get')).toEqual({ kind: 'invalid-token' })
  })

  it('distingue que hace falta el segundo factor', async () => {
    // Literal verificado en DnsWebService.cs:2530
    mockFetch({ status: '2fa-required', errorMessage: 'TOTP required' })
    expect(await apiRequest('user/login')).toEqual({ kind: 'two-factor-required' })
  })

  it('devuelve el mensaje de error del servidor', async () => {
    mockFetch({ status: 'error', errorMessage: 'Invalid username or password for user: admin' })
    expect(await apiRequest('user/login')).toEqual({
      kind: 'error',
      message: 'Invalid username or password for user: admin',
    })
  })

  it('convierte un fallo de red en error legible', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('boom')))
    expect(await apiRequest('user/login')).toEqual({
      kind: 'error',
      message: 'Unable to reach the DNS server.',
    })
  })
})
