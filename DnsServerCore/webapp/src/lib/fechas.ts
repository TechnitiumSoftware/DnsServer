/*
Las formas en que la consola escribe una fecha, replicadas de moment.js —que es
lo que usa upstream y lo que la consola nueva ya no carga.

  · `moment(x).local().format("YYYY-MM-DD HH:mm:ss")` en Sessions, Users, los
    registros de una zona y las entradas de query log.
  · `moment(x).local().format("YYYY-MM-DD HH:mm")` en Cluster, la lista de
    zonas, las concesiones DHCP y las claves DNSSEC.
  · `moment(x).fromNow()` detrás de la fecha, en varias de ellas.

Las fases 4, 8 y 9 se escribieron en paralelo y cada una hizo su copia; al
integrarlas se quedó ésta, que es la única que replica los umbrales de moment
en vez de aproximarlos.

`fromNow` no es «un texto relativo cualquiera»: son cadenas literales de la
interfaz («a few seconds ago», «2 hours ago») con unos umbrales muy concretos.
Se replican los de la locale `en` de moment tal cual, incluida la rareza de que
con los valores por omisión la forma «%d seconds» NUNCA sale: el umbral `ss` es
44 y el `s` es 45, así que todo lo que baja de 45 s cae en «a few seconds».
*/

function dosDigitos(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

/*
El año va a CUATRO dígitos. No es cosmética: `0001-01-01T00:00:00` es el
`default(DateTime)` de .NET y aparece de verdad en cada registro que no se ha
usado nunca. Sin rellenar sale «1-01-01», que no es lo que escribe moment ni se
parece a una fecha.
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

/** `format("YYYY-MM-DD HH:mm")` en hora local. Lo usa la tabla de Cluster. */
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
`Duration.as(unidad)` de moment para una duración hecha sólo de milisegundos.
Los meses NO se cuentan por calendario: `daysToMonths` divide entre
146097/4800 = 30,436875 días, que es el mes medio del calendario gregoriano.
*/
function comoMeses(dias: number): number {
  return (dias * 4800) / 146097
}

/** `moment(x).fromNow()` con la locale `en`. `ahora` se inyecta para poder
 *  probarlo sin depender del reloj. */
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

/** `fecha (hace tanto)`, que es como upstream compone las que llevan las dos. */
export function fechaConAntiguedad(iso: string, ahora?: number): string {
  return `${fechaHora(iso)} (${desdeAhora(iso, ahora)})`
}
