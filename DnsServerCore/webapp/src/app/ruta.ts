import type { Section } from './sections'

/*
La ruta de la consola, en la barra de direcciones de verdad.

Upstream no tiene ninguna: sus pestañas son las de Bootstrap 3, que llaman a
`preventDefault()` y no tocan la URL, así que recargar devuelve siempre al
Dashboard. Esto es, por tanto, un AÑADIDO nuestro y no una paridad recuperada —
queda dicho aquí porque la restricción rectora del proyecto es «solo diseño,
cero funcionalidad» y conviene que quien lea el diff sepa cuál de las dos cosas
está mirando.

**Y no hace falta tocar el servidor.** `www/` se sirve con `UseDefaultFiles()`,
que resuelve `/settings/logging/` a `/settings/logging/index.html` y redirige la
versión sin barra con un 301. El build (ver `vite.config.ts`) emite una carpeta
por ruta, así que la URL existe de verdad: se puede copiar, marcar y recargar.

**La raíz de la aplicación no se puede dar por supuesta.** El servidor honra
`X-Forwarded-Prefix` montando un `PathBase` (`DnsWebService.cs:1943-1945`), así
que la consola puede estar colgando de `/dns/` sin saberlo. Cada copia lleva su
propia ruta en `<meta name="ruta">`, y la raíz sale de restarla al `pathname`.
Esa es la pieza que hace que todo esto funcione detrás de un proxy.
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
 * De dónde cuelga la consola, terminado en `/`.
 *
 * En la portada es el propio `pathname`. En `/dns/settings/logging/` es `/dns/`,
 * y se sabe porque el documento declara que su ruta es `settings/logging`.
 */
/** Lo que dice la barra de direcciones, resuelto contra las secciones visibles. */
export function leerRuta(secciones: Section[]): Ruta | null {
  const base = raizDeLaApp()
  const camino = window.location.pathname
  if (!camino.startsWith(base)) return null

  const [idSeccion, slugSub] = camino.slice(base.length).split('/').filter(Boolean)
  if (idSeccion == null) return null

  const seccion = secciones.find((s) => s.id === idSeccion)
  if (seccion == null) return null

  // Una sub que no existe no invalida la sección: se cae a la primera.
  const sub = slugSub == null ? null : (seccion.subs?.find((t) => aSlug(t) === slugSub) ?? null)
  return { seccion: seccion.id, sub }
}

export function aCamino({ seccion, sub }: Ruta): string {
  return raizDeLaApp() + (sub == null ? `${seccion}/` : `${seccion}/${aSlug(sub)}/`)
}

/**
 * Escribe la ruta. `reemplazar` para la normalización del arranque —que no es
 * una navegación y no debe dejar una entrada en el historial— y empujando para
 * lo que hace el usuario, de modo que el botón «atrás» recorra las secciones en
 * vez de sacarlo de la consola.
 *
 * Se conserva el `search` y NO el `hash`: el hash sólo lo usa el retorno de SSO
 * (`session/boot.ts`), que ya lo ha leído y quiere que desaparezca de la barra.
 */
export function escribirRuta(ruta: Ruta, reemplazar = false): void {
  const nuevo = aCamino(ruta) + window.location.search
  if (window.location.pathname + window.location.search === nuevo) return
  if (reemplazar) window.history.replaceState(null, '', nuevo)
  else window.history.pushState(null, '', nuevo)
}
