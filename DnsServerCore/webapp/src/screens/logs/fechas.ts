/*
`moment(x).local().format("YYYY-MM-DD HH:mm:ss")`, que es como escribe upstream
la marca de tiempo de una entrada de query log (logs.js:512). Sin moment.

Y la conversión inversa: el `<input type="datetime-local">` de los filtros «From»
y «To» entrega una cadena SIN zona (`2026-08-25T00:00`), que upstream pasa por
`moment(...).toISOString()`. Tanto moment como el `Date` del navegador
interpretan esa forma en hora LOCAL, así que el resultado es el mismo.
*/

/* `fechaHora` se unificó en `src/lib/fechas.ts` al integrar las fases 4, 8 y 9. */
export { fechaHora } from '../../lib/fechas'

/** `moment(valor).toISOString()` (logs.js:411). Cadena vacía si no hay valor,
 *  que es lo que upstream manda cuando el campo está en blanco. */
export function aIso(valor: string): string {
  if (valor === '') return ''
  const d = new Date(valor)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}
