/*
The helpers of Administration's editable tables: the "Add …" dropdown that
pushes into a list or into a table.

The serialisation itself is NOT here: it is upstream's `serializeTableData`
(`common.js:282`) and the five screens with an editable table use it, so it lives
in `lib/tabla-serie`. It is re-exported so Administration's four sub-tabs keep
asking for it through this door.
*/
export { serializeTable, type Cell, type TableFailure, type TableResult } from '../../lib/table-serialise'

/*
Administration's four "Add User" / "Add Group" dropdowns. All four behave the
same (auth.js:78-200): `blank` does nothing, `none` EMPTIES the list, and any
other value is appended at the end ONLY if it was not there already.
*/
export const BLANK_OPTION = 'blank'
export const NONE_OPTION = 'none'

/** Variant over a textarea: "Member Of" and "Members". Upstream compares line by
 *  line and guarantees the trailing newline. */
export function addToList(text: string, selection: string): string {
  if (selection === BLANK_OPTION) return text
  if (selection === NONE_OPTION) return ''

  if (text.split('\n').includes(selection)) return text

  let output = text
  if (output.length > 0 && !output.endsWith('\n')) output += '\n'
  return `${output}${selection}\n`
}

/** Variant over a permissions table: it adds the row with the three permissions
 *  false, or empties the table with `none`. */
export function addToTable<T extends { name: string }>(
  rows: readonly T[],
  selection: string,
  blank: (name: string) => T,
): readonly T[] {
  if (selection === BLANK_OPTION) return rows
  if (selection === NONE_OPTION) return []
  if (rows.some((f) => f.name === selection)) return rows
  return [...rows, blank(selection)]
}
