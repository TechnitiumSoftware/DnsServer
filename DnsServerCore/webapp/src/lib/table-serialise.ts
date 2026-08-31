/*
`serializeTableData` (common.js:282), which is how upstream sends an editable
table to the server: Permissions sends two, and SSO sends the scopes and the
group map.

Three details that look minor and are not:

  · The `|` separator is the SAME between columns and between rows. The server
    rebuilds the table by position (`TryQueryOrFormArray(..., 2, ..., '|')`), not
    by different delimiters.
  · A checkbox serialises as `"true"` / `"false"`; a text field, as it is. An
    empty text field ABORTS the whole save with an alert, and one containing `|`
    does too: they are the function's only two validations, and they are
    interface literals.
  · A table with no rows produces the EMPTY string, not `"false"`. The caller
    decides what to do with it: SSO turns it into `"false"` before sending it
    (auth.js:2265 and 2280) and Permissions sends it empty.

It lives in `lib/` because the FIVE screens with an editable table use it, and it
was written once per screen. Out of the five copies came four behaviours: two
allowed an optional cell, this one allows a boolean checkbox and the two in Zones
allowed neither. The algorithm and the two alert literals belong to upstream and
are one single thing; what does belong to each screen is how it LOCATES the
failing cell —a row and a column here, a field `id` in DHCP, a sub-tab in
Settings— and that is why the failure returns the index and the caller translates
it.
*/

export type Cell =
  /** `data-optional` in upstream: the cell that is allowed to be empty. */
  | { type: 'text'; value: string; optional?: boolean }
  | { type: 'casilla'; value: boolean }

export interface TableFailure {
  title: string
  text: string
  /** Index of the row and of the column of the field that has to be focused. */
  row: number
  column: number
}

export type TableResult = { ok: true; value: string } | { ok: false; failure: TableFailure }

export function serializeTable(rows: readonly (readonly Cell[])[]): TableResult {
  const output: string[] = []

  for (let i = 0; i < rows.length; i++) {
    for (let j = 0; j < rows[i].length; j++) {
      const cell = rows[i][j]

      if (cell.type === 'casilla') {
        output.push(cell.value ? 'true' : 'false')
        continue
      }

      if (cell.value === '' && cell.optional !== true) {
        return {
          ok: false,
          failure: {
            title: 'Missing!',
            text: 'Please enter a valid value in the text field in focus.',
            row: i,
            column: j,
          },
        }
      }

      if (cell.value.includes('|')) {
        return {
          ok: false,
          failure: {
            title: 'Invalid Character!',
            text: "Please edit the value in the text field in focus to remove '|' character.",
            row: i,
            column: j,
          },
        }
      }

      output.push(cell.value)
    }
  }

  return { ok: true, value: output.join('|') }
}
