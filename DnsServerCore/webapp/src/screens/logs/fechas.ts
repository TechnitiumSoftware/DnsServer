/*
`moment(x).local().format("YYYY-MM-DD HH:mm:ss")`, which is how upstream writes
the timestamp of a query log entry (logs.js:512). Without moment.

And the inverse conversion: the `<input type="datetime-local">` of the "From" and
"To" filters hands over a string with NO zone (`2026-08-25T00:00`), which
upstream passes through `moment(...).toISOString()`. Both moment and the
browser's `Date` read that form in LOCAL time, so the result is the same.
*/

/* `fechaHora` was unified into `src/lib/fechas.ts` when integrating phases 4, 8 and 9. */
export { fechaHora } from '../../lib/fechas'

/** `moment(valor).toISOString()` (logs.js:411). An empty string if there is no
 *  value, which is what upstream sends when the field is blank. */
export function aIso(valor: string): string {
  if (valor === '') return ''
  const d = new Date(valor)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}
