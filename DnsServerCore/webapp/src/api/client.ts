import { urlApi } from '../app/base'
/*
The console's HTTP client. A replica of the old console's `HTTPRequest` helper
(upstream/master:DnsServerCore/www/js/common.js:28).

Three things that are the server's contract and not our preferences:

  1. Paths go RELATIVE and without a leading slash. The server honours
     X-Forwarded-Prefix and mounts a PathBase (DnsWebService.cs:1943-1945), so a
     leading slash breaks any install behind a proxy with a prefix.

  2. The response is NOT unwrapped. `user/login` and `user/session/get` return
     the session FLAT; every other endpoint wraps it in `response`. Verified
     against a v15.4 instance. Just like upstream, the JSON is handed over as it
     came and the caller decides.

  3. The four values of `status` are `ok`, `2fa-required`, `invalid-token` and
     `error`. Verified in DnsWebService.cs:2475-2543.
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
  /*
  Multipart upload. The console has five: install and update app, import zone,
  import records and restore settings (apps.js:348,392 · zone.js:1273,3039 ·
  main.js:3169). They go with FormData, not with an encoded form, so
  Content-Type must NOT be set by hand: the browser sets it with its boundary.
  The fields of `body` travel inside the FormData too.
  */
  file?: { field: string; archivo: File }
  /** Alternative to `file` when the caller already built the FormData. */
  form?: FormData
  /*
  Plain-text body. One single screen asks for it: importing a zone by pasting
  the file into a textarea sends the raw text with `Content-Type: text/plain`
  instead of multipart (zone.js:1281). The server tells them apart by that type.
  */
  text?: string
}

interface Envelope {
  status?: string
  errorMessage?: string
}

/*
What to do when the server says the session is no longer valid.

Upstream ALWAYS ends the session: `invalid-token` calls `showPageLogin()` —which
clears the token and shows the login— in the sixty-four calls that declare it,
and in the ones that do not, it falls through to the `window.location = "/"` of
`common.js:147`.

Here nobody did. Every screen showed "Invalid token or session expired." and
stayed where it was, with the console apparently usable and every action failing
one after another; to get back in you had to know that a reload was due. Beyond
being awkward, this is an administration console: it must not stay standing with
a session the server has already rejected.

It is solved in a single place —here— and not in the thirty screens, because the
rule is one: `SessionProvider` registers it, since it is the one that holds the
session.
*/
let alCaducar: (() => void) | null = null

export function onSessionExpired(fn: (() => void) | null): void {
  alCaducar = fn
}

export async function apiRequest<T = unknown>(
  path: string,
  opts: ApiOptions = {},
): Promise<ApiOutcome<T>> {
  const { method = 'GET', body, token } = opts

  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  let url = urlApi(`api/${path}`)
  const init: RequestInit & { headers: Record<string, string> } = { method, headers }

  if (opts.form) {
    init.method = 'POST'
    init.body = opts.form
  } else if (opts.text != null) {
    init.method = 'POST'
    headers['Content-Type'] = 'text/plain'
    init.body = opts.text
  } else if (opts.file) {
    const fd = new FormData()
    for (const [k, v] of Object.entries(body ?? {})) fd.append(k, v)
    fd.append(opts.file.field, opts.file.archivo)
    init.method = 'POST'
    init.body = fd
    // No Content-Type by hand: the browser adds the boundary.
  } else if (body) {
    const encoded = new URLSearchParams(body).toString()
    if (method === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      init.body = encoded
    } else {
      url += (url.includes('?') ? '&' : '?') + encoded
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
      alCaducar?.()
      return { kind: 'invalid-token' }
    case '2fa-required':
      return { kind: 'two-factor-required' }
    default:
      return { kind: 'error', message: payload.errorMessage ?? 'Unknown error.' }
  }
}
