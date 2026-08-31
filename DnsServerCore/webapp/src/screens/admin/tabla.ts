/*
Los ayudantes de las tablas editables de Administration: el desplegable «Add
…» que empuja a una lista o a una tabla.

La serialización en sí NO está aquí: es `serializeTableData` de upstream
(`common.js:282`) y la usan las cinco pantallas con tabla editable, así que vive
en `lib/tabla-serie`. Se re-exporta para que las cuatro sub-pestañas de
Administration la sigan pidiendo por esta puerta.
*/
export { serializarTabla, type Celda, type FalloTabla, type ResultadoTabla } from '../../lib/tabla-serie'

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
