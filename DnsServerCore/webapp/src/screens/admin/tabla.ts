/*
`serializeTableData` (common.js:282), que es como upstream manda al servidor una
tabla editable: Permissions manda dos, y SSO manda los scopes y el mapa de
grupos.

Tres detalles que parecen menores y no lo son:

  · El separador `|` es el MISMO entre columnas y entre filas. El servidor
    reconstruye la tabla por posición (`TryQueryOrFormArray(..., 2, ..., '|')`),
    no por delimitadores distintos.
  · Una casilla se serializa como `"true"` / `"false"`; un campo de texto, tal
    cual. Un campo de texto vacío ABORTA el guardado entero con un aviso, y uno
    que contenga `|` también: son las dos únicas validaciones de la función, y
    son literales de interfaz.
  · Una tabla sin filas produce la cadena VACÍA, no `"false"`. Quien llama
    decide qué hacer con ella: SSO la convierte a `"false"` antes de enviarla
    (auth.js:2265 y 2280) y Permissions la manda vacía.
*/

export type Celda = { tipo: 'texto'; valor: string } | { tipo: 'casilla'; valor: boolean }

export interface FalloTabla {
  title: string
  text: string
  /** Índice de la fila y de la columna del campo que hay que enfocar. */
  fila: number
  columna: number
}

export type ResultadoTabla = { ok: true; valor: string } | { ok: false; fallo: FalloTabla }

export function serializarTabla(filas: readonly (readonly Celda[])[]): ResultadoTabla {
  const salida: string[] = []

  for (let i = 0; i < filas.length; i++) {
    for (let j = 0; j < filas[i].length; j++) {
      const celda = filas[i][j]

      if (celda.tipo === 'casilla') {
        salida.push(celda.valor ? 'true' : 'false')
        continue
      }

      if (celda.valor === '') {
        return {
          ok: false,
          fallo: {
            title: 'Missing!',
            text: 'Please enter a valid value in the text field in focus.',
            fila: i,
            columna: j,
          },
        }
      }

      if (celda.valor.includes('|')) {
        return {
          ok: false,
          fallo: {
            title: 'Invalid Character!',
            text: "Please edit the value in the text field in focus to remove '|' character.",
            fila: i,
            columna: j,
          },
        }
      }

      salida.push(celda.valor)
    }
  }

  return { ok: true, valor: salida.join('|') }
}

/*
Los cuatro desplegables «Add User» / «Add Group» de Administration. Los cuatro
se comportan igual (auth.js:78-200): `blank` no hace nada, `none` VACÍA la
lista, y cualquier otro valor lo añade al final SÓLO si no estaba ya.
*/
export const OPCION_BLANK = 'blank'
export const OPCION_NONE = 'none'

/** Variante sobre un textarea: «Member Of» y «Members». Upstream compara línea
 *  a línea y garantiza el salto final. */
export function anadirALaLista(texto: string, seleccion: string): string {
  if (seleccion === OPCION_BLANK) return texto
  if (seleccion === OPCION_NONE) return ''

  if (texto.split('\n').includes(seleccion)) return texto

  let salida = texto
  if (salida.length > 0 && !salida.endsWith('\n')) salida += '\n'
  return `${salida}${seleccion}\n`
}

/** Variante sobre una tabla de permisos: añade la fila con los tres permisos a
 *  falso, o vacía la tabla con `none`. */
export function anadirALaTabla<T extends { nombre: string }>(
  filas: readonly T[],
  seleccion: string,
  nueva: (nombre: string) => T,
): readonly T[] {
  if (seleccion === OPCION_BLANK) return filas
  if (seleccion === OPCION_NONE) return []
  if (filas.some((f) => f.nombre === seleccion)) return filas
  return [...filas, nueva(seleccion)]
}
