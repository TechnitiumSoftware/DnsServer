/*
Console boot. A literal replica of upstream/master:DnsServerCore/www/js/auth.js:24-68.

The order matters and is not arbitrary:

  1. The fragment first. The server reports SSO failures by redirecting to
     `/#error=<message>` (DnsWebService.cs:1797,1806,1816 and eleven more places in
     WebServiceAuthApi.cs). If there is an error, no session is attempted: it is
     shown.

  2. The URL is ALWAYS cleaned with replaceState, error or not.

  3. Cookie before localStorage, and it is DELETED on read. On completing the SSO
     login the server leaves the token in a 2-minute cookie
     (WebServiceAuthApi.cs:663) and redirects to `/`. Deleting it immediately is a
     deliberate security decision of upstream's: it is replicated, not "improved".
*/

export type BootIntent =
  | { kind: 'show-error'; message: string }
  | { kind: 'try-token'; token: string }
  | { kind: 'show-login' }

function readCookie(name: string): string | null {
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim()
    if (trimmed === '') continue
    const eq = trimmed.indexOf('=')
    if (eq < 0) continue
    if (trimmed.slice(0, eq) === name) {
      const value = trimmed.slice(eq + 1)
      return value === '' ? null : value
    }
  }
  return null
}

function deleteCookie(name: string) {
  document.cookie = `${name}=; max-age=0; path=/`
}

export function readBootIntent(): BootIntent {
  const hash = window.location.hash
  const params = new URLSearchParams(hash.length > 0 ? '?' + hash.substring(1) : '')

  /*
  The hash belongs only to the SSO return —"#token=…", "#error=…"— and is wiped
  from the address bar as soon as it has been read, so it is neither shared nor
  left in history. The `pathname` is kept: that is where the console's route
  lives.
  */
  window.history.replaceState(
    null,
    '',
    window.location.protocol + '//' + window.location.host + window.location.pathname + window.location.search,
  )

  const errorMessage = params.get('error')
  if (errorMessage != null) return { kind: 'show-error', message: errorMessage }

  let token = readCookie('token')
  if (token != null) {
    deleteCookie('token')
  } else {
    token = localStorage.getItem('token')
  }

  if (token == null || token === '') return { kind: 'show-login' }
  return { kind: 'try-token', token }
}
