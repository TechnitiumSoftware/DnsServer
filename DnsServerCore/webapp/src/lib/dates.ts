/*
The ways the console writes a date, replicated from moment.js —which is what
upstream uses and what the new console no longer loads.

  · `moment(x).local().format("YYYY-MM-DD HH:mm:ss")` in Sessions, Users, a
    zone's records and the query log entries.
  · `moment(x).local().format("YYYY-MM-DD HH:mm")` in Cluster, the zone list, the
    DHCP leases and the DNSSEC keys.
  · `moment(x).fromNow()` after the date, in several of them.

Phases 4, 8 and 9 were written in parallel and each made its own copy; on
integrating them this one stayed, which is the only one that replicates moment's
thresholds instead of approximating them.

`fromNow` is not "some relative text or other": they are literal interface
strings ("a few seconds ago", "2 hours ago") with very specific thresholds. The
ones of moment's `en` locale are replicated as they are, including the oddity
that with the default values the form "%d seconds" NEVER comes out: the `ss`
threshold is 44 and the `s` one is 45, so everything under 45 s falls into "a few
seconds".
*/

function dosDigitos(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

/*
The year goes to FOUR digits. It is not cosmetic: `0001-01-01T00:00:00` is
.NET's `default(DateTime)` and really does appear on every record that has never
been used. Without padding it comes out as "1-01-01", which is neither what
moment writes nor anything like a date.
*/
function cuatroDigitos(n: number): string {
  return String(n).padStart(4, '0')
}

function parts(iso: string): Date | null {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

/** `format("YYYY-MM-DD HH:mm:ss")` en hora local. */
export function fechaHora(iso: string | null | undefined): string {
  if (iso == null) return ''
  const d = parts(iso)
  if (d == null) return ''
  return (
    `${cuatroDigitos(d.getFullYear())}-${dosDigitos(d.getMonth() + 1)}-${dosDigitos(d.getDate())} ` +
    `${dosDigitos(d.getHours())}:${dosDigitos(d.getMinutes())}:${dosDigitos(d.getSeconds())}`
  )
}

/** `format("YYYY-MM-DD HH:mm")` in local time. The Cluster table uses it. */
export function fechaMinuto(iso: string | null | undefined): string {
  if (iso == null) return ''
  const d = parts(iso)
  if (d == null) return ''
  return (
    `${cuatroDigitos(d.getFullYear())}-${dosDigitos(d.getMonth() + 1)}-${dosDigitos(d.getDate())} ` +
    `${dosDigitos(d.getHours())}:${dosDigitos(d.getMinutes())}`
  )
}

const THRESHOLD = { ss: 44, s: 45, m: 45, h: 22, d: 26, M: 11 }

/*
moment's `Duration.as(unit)` for a duration made only of milliseconds. Months are
NOT counted by calendar: `daysToMonths` divides by 146097/4800 = 30.436875 days,
which is the mean month of the Gregorian calendar.
*/
function asMonths(days: number): number {
  return (days * 4800) / 146097
}

/** `moment(x).fromNow()` with the `en` locale. `ahora` is injected so it can be
 *  tested without depending on the clock. */
export function fromNow(iso: string | null | undefined, now: number = Date.now()): string {
  if (iso == null) return ''
  const d = parts(iso)
  if (d == null) return ''

  const ms = d.getTime() - now
  const futuro = ms > 0
  const abs = Math.abs(ms)

  const seconds = Math.round(abs / 1000)
  const minutes = Math.round(abs / 60000)
  const hours = Math.round(abs / 3600000)
  const days = Math.round(abs / 86400000)
  const months = Math.round(asMonths(abs / 86400000))
  const anos = Math.round(asMonths(abs / 86400000) / 12)

  let text: string
  if (seconds <= THRESHOLD.ss) text = 'a few seconds'
  else if (seconds < THRESHOLD.s) text = `${seconds} seconds`
  else if (minutes <= 1) text = 'a minute'
  else if (minutes < THRESHOLD.m) text = `${minutes} minutes`
  else if (hours <= 1) text = 'an hour'
  else if (hours < THRESHOLD.h) text = `${hours} hours`
  else if (days <= 1) text = 'a day'
  else if (days < THRESHOLD.d) text = `${days} days`
  else if (months <= 1) text = 'a month'
  else if (months < THRESHOLD.M) text = `${months} months`
  else if (anos <= 1) text = 'a year'
  else text = `${anos} years`

  return futuro ? `in ${text}` : `${text} ago`
}

/** `date (time ago)`, which is how upstream composes the ones carrying both. */
export function fechaConAntiguedad(iso: string, now?: number): string {
  return `${fechaHora(iso)} (${fromNow(iso, now)})`
}
