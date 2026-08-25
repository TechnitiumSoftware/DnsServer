/*
Arranque de la consola. Réplica literal de upstream/master:DnsServerCore/www/js/auth.js:24-68.

El orden importa y no es arbitrario:

  1. Fragmento primero. El servidor comunica los fallos de SSO redirigiendo a
     `/#error=<mensaje>` (DnsWebService.cs:1797,1806,1816 y once sitios más en
     WebServiceAuthApi.cs). Si hay error, no se intenta sesión: se muestra.

  2. La URL se limpia SIEMPRE con replaceState, haya error o no.

  3. Cookie antes que localStorage, y se BORRA al leerla. Al completar el login
     por SSO el servidor deja el token en una cookie de 2 minutos
     (WebServiceAuthApi.cs:663) y redirige a `/`. Borrarla en el acto es una
     decisión de seguridad deliberada de upstream: se replica, no se «mejora».
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

  window.history.replaceState(
    null,
    '',
    window.location.protocol + '//' + window.location.host + window.location.pathname,
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
