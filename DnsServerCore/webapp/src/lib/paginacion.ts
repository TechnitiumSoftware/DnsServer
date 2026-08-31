/*
It lives in `lib/` and not under `screens/zones/` because three screens use it:
the zone list, a zone's records and Query Logs. That last one carried its own
copy —`rangoPaginas`, with the same arithmetic letter for letter and tests of its
own— citing `logs.js:571-586` where the other cites `zone.js:880-905`: two places
in upstream doing exactly the same thing.

Upstream's page window (`refreshZones`, zone.js:880-905) and the status text that
goes with it. It is pulled out here because it is arithmetic with two edge cases
and deserves a test of its own.

The window is TEN pages centred five before the current one, and it **slides
backwards** when it reaches the end: on the last page the last ten are visible,
not just one. With fewer than ten pages they are all visible.
*/

export interface Paginacion {
  paginas: number[]
  primera: boolean
  anterior: number | null
  siguiente: number | null
  ultima: boolean
}

export function ventanaDePaginas(pageNumber: number, totalPages: number): Paginacion {
  let inicio = pageNumber - 5
  if (inicio < 1) inicio = 1

  let fin = inicio + 9
  if (fin > totalPages) {
    inicio -= fin - totalPages
    fin = totalPages
    if (inicio < 1) inicio = 1
  }

  const paginas: number[] = []
  for (let i = inicio; i <= fin; i++) paginas.push(i)

  return {
    paginas,
    primera: pageNumber > 1,
    anterior: pageNumber > 1 ? pageNumber - 1 : null,
    siguiente: pageNumber < totalPages ? pageNumber + 1 : null,
    ultima: pageNumber < totalPages,
  }
}

/**
 * Upstream's `statusHtml`, literal. With zero items the whole phrase changes to
 * "0 zones", it does not say "0-0 of 0".
 */
export function textoDeEstado(
  primeraFila: number,
  enPagina: number,
  total: number,
  pageNumber: number,
  totalPages: number,
  sustantivo: string,
): string {
  if (enPagina === 0) return `0 ${sustantivo}`
  const ultima = primeraFila + enPagina - 1
  return `${primeraFila}-${ultima} (${enPagina}) of ${total} ${sustantivo} (page ${pageNumber} of ${totalPages})`
}
