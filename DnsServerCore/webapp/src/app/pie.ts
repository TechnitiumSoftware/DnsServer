/*
Los enlaces del pie de upstream.

Viven en un `div#footer` que cuelga directamente del `body` (no de `#pageLogin`
ni de `#pageMain`), así que en upstream se ven en TODAS las pantallas: la de
login y la consola entera. Aquí faltaban por completo, y dos de ellos
—`technitium.com` y `dnsclient.net`— no aparecían en ningún otro sitio, así que
se habían perdido del producto.

La lista vive en un módulo suyo porque la pintan dos sitios distintos —el panel
lateral y la pantalla de login—, y una lista de enlaces repetida es una lista
que se queda a medias en cuanto alguien toca uno.

«About» no está: en upstream es el sexto enlace del pie y aquí es una sección
del panel lateral, así que ya se llega.
*/
export interface EnlaceDePie {
  texto: string
  href: string
  /*
  Nombre accesible alternativo, sólo cuando el visible choca con otro enlace de
  la misma pantalla. Pasa con «DNS Client»: es a la vez una sección del panel
  (`/dnsclient/`) y el otro producto de Technitium (`dnsclient.net`), así que
  quien navegue por lista de enlaces oía dos veces lo mismo apuntando a sitios
  distintos. El nombre empieza por el texto visible, que es lo que exige el
  criterio «label in name».
  */
  nombre?: string
}

export const PIE: EnlaceDePie[] = [
  { texto: 'Technitium', href: 'https://technitium.com/' },
  { texto: 'Blog', href: 'https://blog.technitium.com/' },
  { texto: 'Donate', href: 'https://go.technitium.com/?id=35' },
  { texto: 'DNS Client', href: 'https://dnsclient.net/', nombre: 'DNS Client at dnsclient.net' },
  { texto: 'GitHub', href: 'https://github.com/TechnitiumSoftware/DnsServer' },
]

/*
El crédito del tema. NO es de upstream: es lo único del pie que esta consola
añade, y por eso vive fuera de `PIE` y no de la lista que compara
`dev/check-paridad-controles.mjs`. Quien lea esto tiene que poder distinguir de
un vistazo qué es paridad y qué es añadido nuestro.

Va en su propia línea y no como sexto enlace: los cinco de arriba son destinos
del PRODUCTO y esto es una autoría. Metido en la misma fila, con las mismas
barras, se leería como un sitio más de Technitium.
*/
export const CREDITO_TEMA = {
  texto: 'agarmoli',
  href: 'https://github.com/agarmoli',
  /* Empieza por el texto visible, que es lo que exige «label in name». */
  nombre: 'agarmoli on GitHub',
}
