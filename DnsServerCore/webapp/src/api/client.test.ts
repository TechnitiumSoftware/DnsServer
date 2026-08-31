import { describe, expect, it, vi, beforeEach } from 'vitest'
import { apiRequest } from './client'
import { olvidarRaiz } from '../app/base'

function mockFetch(payload: unknown) {
  const spy = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => payload })
  vi.stubGlobal('fetch', spy)
  return spy
}

beforeEach(() => vi.unstubAllGlobals())

describe('apiRequest', () => {
  it('hands over the raw JSON when the status is ok', async () => {
    // user/login and user/session/get return the session FLAT, with no `response`
    // wrapper. Everything else does wrap it. That is why the client does not
    // unwrap: like upstream's HTTPRequest, it hands over the JSON as it came.
    mockFetch({ status: 'ok', token: 'abc', displayName: 'Administrator' })
    const r = await apiRequest('user/login')
    expect(r).toEqual({ kind: 'ok', data: { status: 'ok', token: 'abc', displayName: 'Administrator' } })
  })

  it('hands over the wrapped ones too, untouched', async () => {
    mockFetch({ status: 'ok', response: { zones: [] } })
    const r = await apiRequest('zones/list')
    expect(r).toEqual({ kind: 'ok', data: { status: 'ok', response: { zones: [] } } })
  })

  it('sends the token as a Bearer header', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/session/get', { token: 'abc123' })
    expect(spy.mock.calls[0][1].headers.Authorization).toBe('Bearer abc123')
  })

  /*
  They used to be relative so as to survive `X-Forwarded-Prefix`, and that
  stopped working when the console's routes became real ones: from
  `/settings/logging/`, a relative `api/status` asks for
  `/settings/logging/api/status` and gets a 404. Checked in the browser. Now they
  hang off the application's root, which still knows the prefix.
  */
  it('hangs the paths off the application root, not off the current directory', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/login')
    expect(spy.mock.calls[0][0]).toBe('/api/user/login')
  })

  it('and honours the proxy prefix', async () => {
    const meta = document.createElement('meta')
    meta.setAttribute('name', 'ruta')
    meta.setAttribute('content', 'settings/logging')
    document.head.appendChild(meta)
    window.history.replaceState(null, '', '/dns/settings/logging/')
    olvidarRaiz()

    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/login')
    expect(spy.mock.calls[0][0]).toBe('/dns/api/user/login')

    meta.remove()
    window.history.replaceState(null, '', '/')
    olvidarRaiz()
  })

  it('puts the body in the query when it is a GET', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('zones/list', { body: { zone: 'casa.test' } })
    expect(spy.mock.calls[0][0]).toBe('/api/zones/list?zone=casa.test')
  })

  it('encodes the body as a form when it is a POST', async () => {
    const spy = mockFetch({ status: 'ok' })
    await apiRequest('user/login', { method: 'POST', body: { user: 'admin', pass: 'a b&c' } })
    const [url, init] = spy.mock.calls[0]
    expect(url).toBe('/api/user/login')
    expect(init.body).toBe('user=admin&pass=a+b%26c')
    expect(init.headers['Content-Type']).toBe('application/x-www-form-urlencoded')
  })

  it('tells an invalid token apart', async () => {
    mockFetch({ status: 'invalid-token', errorMessage: 'Invalid token or session expired.' })
    expect(await apiRequest('user/session/get')).toEqual({ kind: 'invalid-token' })
  })

  it('tells apart that the second factor is needed', async () => {
    // Literal verificado en DnsWebService.cs:2530
    mockFetch({ status: '2fa-required', errorMessage: 'TOTP required' })
    expect(await apiRequest('user/login')).toEqual({ kind: 'two-factor-required' })
  })

  it('returns the error message from the server', async () => {
    mockFetch({ status: 'error', errorMessage: 'Invalid username or password for user: admin' })
    expect(await apiRequest('user/login')).toEqual({
      kind: 'error',
      message: 'Invalid username or password for user: admin',
    })
  })

  it('turns a network failure into a readable error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('boom')))
    expect(await apiRequest('user/login')).toEqual({
      kind: 'error',
      message: 'Unable to reach the DNS server.',
    })
  })
})

describe('multipart uploads', () => {
  it('sends FormData and does NOT set Content-Type by hand', async () => {
    const spy = mockFetch({ status: 'ok' })
    const archivo = new File(['zona'], 'casa.test.zone', { type: 'text/plain' })
    await apiRequest('zones/import', { token: 't', body: { zone: 'casa.test' }, file: { campo: 'fileZone', archivo } })
    const [url, init] = spy.mock.calls[0]
    expect(url).toBe('/api/zones/import')
    expect(init.method).toBe('POST')
    expect(init.body).toBeInstanceOf(FormData)
    // The browser sets the boundary; setting it by hand breaks the upload.
    expect(init.headers['Content-Type']).toBeUndefined()
  })

  it('the ordinary fields travel inside the FormData, not in the query', async () => {
    const spy = mockFetch({ status: 'ok' })
    const archivo = new File(['x'], 'a.txt')
    await apiRequest('zones/import', { body: { zone: 'casa.test', overwrite: 'true' }, file: { campo: 'f', archivo } })
    const [url, init] = spy.mock.calls[0]
    expect(url).not.toContain('?')
    const fd = init.body as FormData
    expect(fd.get('zone')).toBe('casa.test')
    expect(fd.get('overwrite')).toBe('true')
    expect(fd.get('f')).toBeInstanceOf(File)
  })
})
