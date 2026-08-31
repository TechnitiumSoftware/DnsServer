import { Icon } from './Icon'
import styles from './Pagination.module.css'
import type { Pagination as Window } from '../lib/pagination'

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
  window,
  current,
  last,
  onIr,
}: {
  window: Window
  current: number
  /** Which number to ask for as "last". `-1` lets the server resolve it. */
  last: number
  onIr: (page: number) => void
}) {
  return (
    <span className={styles.pg}>
      {window.first && (
        <button type="button" className={styles.pgb} aria-label="First" onClick={() => onIr(1)}>
          <Icon name="first" size={14} />
        </button>
      )}
      {window.previous != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Previous"
          onClick={() => onIr(window.previous!)}
        >
          <Icon name="chevronLeft" size={14} />
        </button>
      )}
      {window.pages.map((p) => (
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
      {window.next != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Next"
          onClick={() => onIr(window.next!)}
        >
          <Icon name="chevronRight" size={14} />
        </button>
      )}
      {window.last && (
        <button type="button" className={styles.pgb} aria-label="Last" onClick={() => onIr(last)}>
          <Icon name="last" size={14} />
        </button>
      )}
    </span>
  )
}
