import type { Section } from './sections'

/*
La ruta de la consola, en el hash.

Upstream no tiene ninguna: sus pestañas son las de Bootstrap 3, que llaman a
`preventDefault()` y no tocan la URL, así que recargar devuelve siempre al
Dashboard. Esto es, por tanto, un AÑADIDO nuestro y no una paridad recuperada —
queda dicho aquí porque la restricción rectora del proyecto es «solo diseño,
cero funcionalidad» y conviene que el que lea el diff sepa cuál de las dos cosas
está mirando.

**Va en el hash y no en la ruta porque el servidor no deja otra.** `www/` se
sirve con un `PhysicalFileProvider` y `UseStaticFiles` sin ningún fallback de
SPA: `GET /zones` devuelve 404, comprobado contra la instancia. Un enrutado por
ruta real exigiría tocar C#, y la regla del proyecto es no tocar el servidor.

Formato: `#/<sección>` y `#/<sección>/<sub>`. El prefijo `#/` no es decorativo:
es lo que permite distinguir una ruta del retorno de SSO, que llega como
`#token=…` o `#error=…` y que `session/boot.ts` tiene que seguir borrando.
*/

/** `Proxy & Forwarders` → `proxy-forwarders`. Sin acentos ni `&`: es una URL. */
export function aSlug(etiqueta: string): string {
  return etiqueta
    .toLowerCase()
    .replace(/&/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

export interface Ruta {
  seccion: string
  sub: string | null
}

/** Lo que dice la barra de direcciones, resuelto contra las secciones visibles. */
export function leerRuta(secciones: Section[]): Ruta | null {
  const hash = window.location.hash
  if (!hash.startsWith('#/')) return null

  const [idSeccion, slugSub] = hash.slice(2).split('/')
  const seccion = secciones.find((s) => s.id === idSeccion)
  if (seccion == null) return null

  // Una sub que no existe no invalida la sección: se cae a la primera.
  const sub = slugSub == null ? null : (seccion.subs?.find((t) => aSlug(t) === slugSub) ?? null)
  return { seccion: seccion.id, sub }
}

export function aHash({ seccion, sub }: Ruta): string {
  return sub == null ? `#/${seccion}` : `#/${seccion}/${aSlug(sub)}`
}

/**
 * Escribe la ruta. `reemplazar` para la normalización del arranque —que no es
 * una navegación y no debe dejar una entrada en el historial— y empujando para
 * lo que hace el usuario, de modo que el botón «atrás» recorra las secciones en
 * vez de sacarlo de la consola.
 */
export function escribirRuta(ruta: Ruta, reemplazar = false): void {
  const nuevo = aHash(ruta)
  if (window.location.hash === nuevo) return
  if (reemplazar) window.history.replaceState(null, '', nuevo)
  else window.location.hash = nuevo
}
