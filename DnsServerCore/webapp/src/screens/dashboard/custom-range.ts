/*
The Dashboard's custom range.

`Custom` was a dead button: it marked itself as pressed, the tiles stayed at "—"
and nowhere did it appear where to put the dates. The API layer already accepted
`{start, end}` from the beginning; what was missing was asking for them.

The odd part is here, in a pure function, because it is the only thing in all of
this with a rule worth testing: **how a date is turned into an instant**.

Upstream (`main.js:2604-2612`) does something that looks like an oversight and is
not: if the range fits in seven days or fewer, it reads the dates in the
browser's LOCAL zone; if it is longer, in UTC. The reason is that under a week
the server returns statistics by the hour —and hours have to line up with the
clock of whoever is looking— and above that it returns them by day, which the
server groups in UTC. Reading it all the same way would shift one of the two
views.
*/

/** The two ISO instants the API expects, with the seven-day rule. */
export function instantesDelRango(inicio: string, fin: string): { start: string; end: string } {
  const dias = (Date.parse(`${fin}T00:00:00Z`) - Date.parse(`${inicio}T00:00:00Z`)) / 86_400_000 + 1
  const aIso = (d: string) => new Date(dias > 7 ? `${d}T00:00:00Z` : `${d}T00:00:00`).toISOString()
  return { start: aIso(inicio), end: aIso(fin) }
}

/**
 * What is still to be filled in, with upstream's literal text
 * (`main.js:2591-2601`). `null` when the range is complete.
 */
export function loQueFalta(inicio: string, fin: string): string | null {
  if (inicio === '') return 'Please select a start date.'
  if (fin === '') return 'Please select an end date.'
  return null
}
