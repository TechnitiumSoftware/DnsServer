import type { ReactNode } from 'react'
import styles from './Empty.module.css'

/*
An empty state is painted in two ways and no more:

  · `Empty` — a REGION's empty state, the one that takes the place of the table or
    grid that has no rows. Dotted box, centred, with a title and, if the user can
    do something about it, the button that does it.
  · `Empty compacto` — the empty state INSIDE a panel, a muted line that does not
    compete with the panel containing it.

And `Loading` and `Fallo` are the same slot before the data: one while it travels
and the other when it never arrived. Same place and same weight as the empty state
they replace, so the screen does not jump when it resolves.

`Fallo` was written by hand in four modules —`.fail` in Settings, DHCP, Logs and
Administration— with the same four values `.cargando` already had here.
*/

export function Empty({
  titulo,
  children,
  actions,
  compacto = false,
}: {
  /** What it is that is not there. Region empty state only. */
  titulo?: string
  /** Why it is not there, or what to do so that it is. */
  children?: ReactNode
  actions?: ReactNode
  compacto?: boolean
}) {
  if (compacto) return <div className={styles.line}>{children}</div>

  return (
    <div className={styles.caja}>
      {titulo != null && <span className={styles.titulo}>{titulo}</span>}
      {children}
      {actions != null && <div className={styles.actions}>{actions}</div>}
    </div>
  )
}

export function Loading({
  children = 'Loading…',
  compacto = false,
}: {
  /** What is loading, when saying so helps: "Loading DS records…". */
  children?: ReactNode
  compacto?: boolean
}) {
  return <div className={`${styles.loading}${compacto ? ` ${styles.line}` : ''}`}>{children}</div>
}

/** The data never arrived. It fills the same slot as the `Loading` it replaces. */
export function Fallo({ children }: { children: ReactNode }) {
  return <div className={styles.loading}>{children}</div>
}
