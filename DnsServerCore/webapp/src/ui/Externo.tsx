import type { ReactNode } from 'react'
import styles from './Externo.module.css'

/*
The links that lead out of the console.

They are here and not scattered because a review found they had been going missing
one at a time: upstream's sentence stayed and the destination disappeared —"read
the change log" with no change log, "Use ZONEMD to Validate Zone" with no RFC—.
With a single place where they are written, `dev/check-paridad-controles.mjs` can
verify by list that none is missing.

Two shapes, which is what upstream has:

- `Externo`, inside a sentence: "validated using the [ZONEMD] record".
- `Ayuda`, the standalone line at the foot of a panel or a dialog: "Help: …".
*/
export function Externo({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer">
      {children}
    </a>
  )
}

/**
 * The help line. It is not a link inside a sentence, so WCAG's target-size
 * exception does not apply to it: it carries a box of its own.
 */
export function Ayuda({ href, children }: { href: string; children: ReactNode }) {
  return (
    <div className={styles.ayuda}>
      <Externo href={href}>{children}</Externo>
    </div>
  )
}
