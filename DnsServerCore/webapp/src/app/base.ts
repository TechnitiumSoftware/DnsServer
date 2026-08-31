/*
Where the console hangs from.

It cannot be assumed to be `/`: the server honours `X-Forwarded-Prefix` by mounting
a `PathBase` (`DnsWebService.cs:1943-1945`), so behind a proxy the console can live
at `/dns/`. And ever since the routes became real —`/settings/logging/`— relative
paths do not work either: `api/status` from there requests
`/settings/logging/api/status`, which is a 404. Verified in the browser before
fixing it.

Each generated `index.html` declares its own route in a `<meta>`, and the root
comes from subtracting those segments from the `pathname`.
*/

function calcular(): string {
  const route = document.querySelector('meta[name="ruta"]')?.getAttribute('content')
  const camino = window.location.pathname
  if (route == null || route === '') return camino.endsWith('/') ? camino : camino + '/'

  const sobra = route.split('/').length
  const parts = camino.split('/').filter(Boolean)
  const prefijo = parts.slice(0, Math.max(0, parts.length - sobra))
  return prefijo.length === 0 ? '/' : `/${prefijo.join('/')}/`
}

/*
It is computed ONCE and frozen. The `<meta>` belongs to the document the server
served and does not change on navigation: as soon as the application pushes
`/settings/logging/` onto a document that said `dashboard`, subtracting its
segments would give a different root on every hop. The root is a property of where
the console is mounted, not of where the user is.
*/
let cache: string | null = null

export function raizDeLaApp(): string {
  cache ??= calcular()
  return cache
}

/** For the tests only, which change root between cases. */
export function olvidarRaiz(): void {
  cache = null
}

/** An endpoint's URL, hanging from the real root. */
export function urlApi(camino: string): string {
  return raizDeLaApp() + camino
}

/**
 * The same for a file from `public/` —the logo, the `loader.gif`s—. A relative
 * `src` also breaks from a two-level route: `img/logo.png` at
 * `/settings/logging/` requests `/settings/logging/img/logo.png`.
 */
export function urlPublica(camino: string): string {
  return raizDeLaApp() + camino
}
