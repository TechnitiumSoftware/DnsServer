/*
Vive en `lib/` y no bajo `screens/zones/` porque la usan tres pantallas: la lista
de zonas, los registros de una zona y Query Logs. Esta última llevaba su propia
copia —`rangoPaginas`, con la misma aritmética letra por letra y sus propias
pruebas—, citando `logs.js:571-586` donde la otra cita `zone.js:880-905`: dos
sitios de upstream que hacen exactamente lo mismo.

La ventana de páginas de upstream (`refreshZones`, zone.js:880-905) y el texto
de estado que la acompaña. Se extrae aquí porque es aritmética con dos casos
borde y merece prueba propia.

La ventana es de DIEZ páginas centradas cinco antes de la actual, y **se
desplaza hacia atrás** cuando toca el final: en la última página se ven las diez
últimas, no una sola. Con menos de diez páginas se ven todas.
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
 * `statusHtml` de upstream, literal. Con cero elementos la frase entera cambia
 * a «0 zones», no dice «0-0 of 0».
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
