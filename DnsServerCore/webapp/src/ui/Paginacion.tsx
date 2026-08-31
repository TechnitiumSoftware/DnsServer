import { Icono } from './Icono'
import styles from './Pagination.module.css'
import type { Pagination as Ventana } from '../lib/paginacion'

/*
The page bar: first, previous, the window of ten, next and last.

It was written by hand on three screens —the zone list, a zone's records and Query
Logs— with the same markup and the same string of buttons. The arithmetic already
lived in one place (`lib/paginacion.ts`, which is tested on its own); what was
missing was the buttons doing the same.

The only thing that really differed between the three is HOW the last page is
asked for: the zone list and Query Logs send `-1` and let the server resolve it
—which is what upstream does— and a zone's records compute it client-side because
they have them all. That is why `ultima` is a parameter and not hard-coded.
*/
export function Pagination({
  ventana,
  current,
  last,
  onIr,
}: {
  ventana: Ventana
  current: number
  /** Which number to ask for as "last". `-1` lets the server resolve it. */
  last: number
  onIr: (page: number) => void
}) {
  return (
    <span className={styles.pg}>
      {ventana.primera && (
        <button type="button" className={styles.pgb} aria-label="First" onClick={() => onIr(1)}>
          <Icono name="first" tam={14} />
        </button>
      )}
      {ventana.previous != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Previous"
          onClick={() => onIr(ventana.previous!)}
        >
          <Icono name="chevronIzquierda" tam={14} />
        </button>
      )}
      {ventana.pages.map((p) => (
        <button
          key={p}
          type="button"
          className={styles.pgb}
          aria-current={p === current}
          onClick={() => onIr(p)}
        >
          {p}
        </button>
      ))}
      {ventana.next != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Next"
          onClick={() => onIr(ventana.next!)}
        >
          <Icono name="chevronDerecha" tam={14} />
        </button>
      )}
      {ventana.last && (
        <button type="button" className={styles.pgb} aria-label="Last" onClick={() => onIr(last)}>
          <Icono name="last" tam={14} />
        </button>
      )}
    </span>
  )
}
