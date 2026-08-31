import type { Section } from './sections'

/*
The console's route, in the real address bar.

Upstream has none: its tabs are Bootstrap 3's, which call `preventDefault()` and
never touch the URL, so reloading always returns to the Dashboard. This is
therefore an ADDITION of ours and not recovered parity — it is stated here because
the project's governing constraint is "design only, zero functionality" and whoever
reads the diff should know which of the two they are looking at.

**And it needs no server change.** `www/` is served with `UseDefaultFiles()`, which
resolves `/settings/logging/` to `/settings/logging/index.html` and redirects the
slash-less version with a 301. The build (see `vite.config.ts`) emits one folder
per route, so the URL genuinely exists: it can be copied, bookmarked and reloaded.

**The application root cannot be assumed.** The server honours
`X-Forwarded-Prefix` by mounting a `PathBase` (`DnsWebService.cs:1943-1945`), so the
console may be hanging off `/dns/` without knowing it. Each copy carries its own
route in `<meta name="ruta">`, and the root comes from subtracting it from the
`pathname`. That is the piece that makes all of this work behind a proxy.
*/

export { aSlug } from './slug'
import { aSlug } from './slug'
export { olvidarRaiz, raizDeLaApp } from './base'
import { raizDeLaApp } from './base'

export interface Ruta {
  seccion: string
  sub: string | null
}

/**
 * Where the console hangs from, ending in `/`.
 *
 * On the front page it is the `pathname` itself. At `/dns/settings/logging/` it is
 * `/dns/`, and that is known because the document declares its route to be
 * `settings/logging`.
 */
/** What the address bar says, resolved against the visible sections. */
export function leerRuta(secciones: Section[]): Ruta | null {
  const base = raizDeLaApp()
  const camino = window.location.pathname
  if (!camino.startsWith(base)) return null

  const [idSeccion, slugSub] = camino.slice(base.length).split('/').filter(Boolean)
  if (idSeccion == null) return null

  const seccion = secciones.find((s) => s.id === idSeccion)
  if (seccion == null) return null

  // A sub that does not exist does not invalidate the section: it falls to the first.
  const sub = slugSub == null ? null : (seccion.subs?.find((t) => aSlug(t) === slugSub) ?? null)
  return { seccion: seccion.id, sub }
}

export function aCamino({ seccion, sub }: Ruta): string {
  return raizDeLaApp() + (sub == null ? `${seccion}/` : `${seccion}/${aSlug(sub)}/`)
}

/**
 * Writes the route. `reemplazar` for the boot normalisation —which is not a
 * navigation and must not leave a history entry— and pushing for what the user
 * does, so the back button walks the sections instead of taking them out of the
 * console.
 *
 * The `search` is kept and the `hash` is NOT: the hash is only used by the SSO
 * return (`session/boot.ts`), which has already read it and wants it gone from the
 * bar.
 */
export function escribirRuta(ruta: Ruta, reemplazar = false): void {
  const nuevo = aCamino(ruta) + window.location.search
  if (window.location.pathname + window.location.search === nuevo) return
  if (reemplazar) window.history.replaceState(null, '', nuevo)
  else window.history.pushState(null, '', nuevo)
}
