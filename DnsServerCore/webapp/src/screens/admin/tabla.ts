/*
The helpers of Administration's editable tables: the "Add …" dropdown that
pushes into a list or into a table.

The serialisation itself is NOT here: it is upstream's `serializeTableData`
(`common.js:282`) and the five screens with an editable table use it, so it lives
in `lib/tabla-serie`. It is re-exported so Administration's four sub-tabs keep
asking for it through this door.
*/
export { serializarTabla, type Celda, type FalloTabla, type ResultadoTabla } from '../../lib/tabla-serie'

/*
Administration's four "Add User" / "Add Group" dropdowns. All four behave the
same (auth.js:78-200): `blank` does nothing, `none` EMPTIES the list, and any
other value is appended at the end ONLY if it was not there already.
*/
export const OPCION_BLANK = 'blank'
export const OPCION_NONE = 'none'

/** Variant over a textarea: "Member Of" and "Members". Upstream compares line by
 *  line and guarantees the trailing newline. */
export function anadirALaLista(texto: string, seleccion: string): string {
  if (seleccion === OPCION_BLANK) return texto
  if (seleccion === OPCION_NONE) return ''

  if (texto.split('\n').includes(seleccion)) return texto

  let salida = texto
  if (salida.length > 0 && !salida.endsWith('\n')) salida += '\n'
  return `${salida}${seleccion}\n`
}

/** Variant over a permissions table: it adds the row with the three permissions
 *  false, or empties the table with `none`. */
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
