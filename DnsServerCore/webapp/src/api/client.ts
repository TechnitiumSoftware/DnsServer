/*
Cliente HTTP de la consola. Réplica del helper `HTTPRequest` de la consola
antigua (upstream/master:DnsServerCore/www/js/common.js:28).

Tres cosas que son contrato del servidor y no preferencias nuestras:

  1. Las rutas van en RELATIVO y sin barra inicial. El servidor honra
     X-Forwarded-Prefix y monta un PathBase (DnsWebService.cs:1943-1945), así
     que una barra inicial rompe cualquier instalación tras un proxy con prefijo.

  2. NO se desenvuelve la respuesta. `user/login` y `user/session/get` devuelven
     la sesión PLANA; el resto de endpoints la envuelven en `response`.
     Verificado contra una instancia v15.4. Igual que upstream, aquí se entrega
     el JSON tal cual y decide quien llama.

  3. Los cuatro valores de `status` son `ok`, `2fa-required`, `invalid-token` y
     `error`. Verificados en DnsWebService.cs:2475-2543.
*/

export type ApiOutcome<T = unknown> =
  | { kind: 'ok'; data: T }
  | { kind: 'error'; message: string }
  | { kind: 'invalid-token' }
  | { kind: 'two-factor-required' }

export interface ApiOptions {
  method?: 'GET' | 'POST'
  body?: Record<string, string>
  token?: string | null
}

interface Envelope {
  status?: string
  errorMessage?: string
}

export async function apiRequest<T = unknown>(
  path: string,
  opts: ApiOptions = {},
): Promise<ApiOutcome<T>> {
  const { method = 'GET', body, token } = opts

  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  let url = `api/${path}`
  const init: RequestInit & { headers: Record<string, string> } = { method, headers }

  if (body) {
    const encoded = new URLSearchParams(body).toString()
    if (method === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      init.body = encoded
    } else {
      url += `?${encoded}`
    }
  }

  let payload: Envelope
  try {
    const res = await fetch(url, init)
    payload = (await res.json()) as Envelope
  } catch {
    return { kind: 'error', message: 'Unable to reach the DNS server.' }
  }

  switch (payload.status) {
    case 'ok':
      return { kind: 'ok', data: payload as T }
    case 'invalid-token':
      return { kind: 'invalid-token' }
    case '2fa-required':
      return { kind: 'two-factor-required' }
    default:
      return { kind: 'error', message: payload.errorMessage ?? 'Unknown error.' }
  }
}
