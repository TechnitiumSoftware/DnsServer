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

function partes(iso: string): Date | null {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

/** `format("YYYY-MM-DD HH:mm:ss")` en hora local. */
export function fechaHora(iso: string | null | undefined): string {
  if (iso == null) return ''
  const d = partes(iso)
  if (d == null) return ''
  return (
    `${cuatroDigitos(d.getFullYear())}-${dosDigitos(d.getMonth() + 1)}-${dosDigitos(d.getDate())} ` +
    `${dosDigitos(d.getHours())}:${dosDigitos(d.getMinutes())}:${dosDigitos(d.getSeconds())}`
  )
}

/** `format("YYYY-MM-DD HH:mm")` in local time. The Cluster table uses it. */
export function fechaMinuto(iso: string | null | undefined): string {
  if (iso == null) return ''
  const d = partes(iso)
  if (d == null) return ''
  return (
    `${cuatroDigitos(d.getFullYear())}-${dosDigitos(d.getMonth() + 1)}-${dosDigitos(d.getDate())} ` +
    `${dosDigitos(d.getHours())}:${dosDigitos(d.getMinutes())}`
  )
}

const UMBRAL = { ss: 44, s: 45, m: 45, h: 22, d: 26, M: 11 }

/*
moment's `Duration.as(unit)` for a duration made only of milliseconds. Months are
NOT counted by calendar: `daysToMonths` divides by 146097/4800 = 30.436875 days,
which is the mean month of the Gregorian calendar.
*/
function comoMeses(dias: number): number {
  return (dias * 4800) / 146097
}

/** `moment(x).fromNow()` with the `en` locale. `ahora` is injected so it can be
 *  tested without depending on the clock. */
export function desdeAhora(iso: string | null | undefined, ahora: number = Date.now()): string {
  if (iso == null) return ''
  const d = partes(iso)
  if (d == null) return ''

  const ms = d.getTime() - ahora
  const futuro = ms > 0
  const abs = Math.abs(ms)

  const segundos = Math.round(abs / 1000)
  const minutos = Math.round(abs / 60000)
  const horas = Math.round(abs / 3600000)
  const dias = Math.round(abs / 86400000)
  const meses = Math.round(comoMeses(abs / 86400000))
  const anos = Math.round(comoMeses(abs / 86400000) / 12)

  let texto: string
  if (segundos <= UMBRAL.ss) texto = 'a few seconds'
  else if (segundos < UMBRAL.s) texto = `${segundos} seconds`
  else if (minutos <= 1) texto = 'a minute'
  else if (minutos < UMBRAL.m) texto = `${minutos} minutes`
  else if (horas <= 1) texto = 'an hour'
  else if (horas < UMBRAL.h) texto = `${horas} hours`
  else if (dias <= 1) texto = 'a day'
  else if (dias < UMBRAL.d) texto = `${dias} days`
  else if (meses <= 1) texto = 'a month'
  else if (meses < UMBRAL.M) texto = `${meses} months`
  else if (anos <= 1) texto = 'a year'
  else texto = `${anos} years`

  return futuro ? `in ${texto}` : `${texto} ago`
}

/** `date (time ago)`, which is how upstream composes the ones carrying both. */
export function fechaConAntiguedad(iso: string, ahora?: number): string {
  return `${fechaHora(iso)} (${desdeAhora(iso, ahora)})`
}
