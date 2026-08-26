/*
De dónde cuelga la consola.

No se puede dar por supuesto que sea `/`: el servidor honra `X-Forwarded-Prefix`
montando un `PathBase` (`DnsWebService.cs:1943-1945`), así que detrás de un proxy
la consola puede vivir en `/dns/`. Y desde que las rutas son reales
—`/settings/logging/`— tampoco vale usar rutas relativas: `api/status` desde ahí
pide `/settings/logging/api/status`, que es un 404. Comprobado en el navegador
antes de arreglarlo.

Cada `index.html` generado declara su propia ruta en un `<meta>`, y la raíz sale
de restarle esos segmentos al `pathname`.
*/

function calcular(): string {
  const ruta = document.querySelector('meta[name="ruta"]')?.getAttribute('content')
  const camino = window.location.pathname
  if (ruta == null || ruta === '') return camino.endsWith('/') ? camino : camino + '/'

  const sobra = ruta.split('/').length
  const partes = camino.split('/').filter(Boolean)
  const prefijo = partes.slice(0, Math.max(0, partes.length - sobra))
  return prefijo.length === 0 ? '/' : `/${prefijo.join('/')}/`
}

/*
Se calcula UNA vez y se congela. El `<meta>` es el del documento que sirvió el
servidor y no cambia al navegar: en cuanto la aplicación empuja
`/settings/logging/` sobre un documento que decía `dashboard`, restar sus
segmentos daría una raíz distinta en cada salto. La raíz es una propiedad de
dónde está montada la consola, no de dónde está el usuario.
*/
let cache: string | null = null

export function raizDeLaApp(): string {
  cache ??= calcular()
  return cache
}

/** Sólo para las pruebas, que cambian de raíz entre casos. */
export function olvidarRaiz(): void {
  cache = null
}

/** La URL de un endpoint, colgando de la raíz de verdad. */
export function urlApi(camino: string): string {
  return raizDeLaApp() + camino
}
