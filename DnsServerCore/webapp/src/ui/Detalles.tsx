import type { ReactNode } from 'react'
import { Icono } from './Icono'
import styles from './Detalles.module.css'

/** A `<details>` with the icon set's chevron. See the styles module. */
export function Detalles({
  summary,
  children,
  className,
}: {
  summary: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <details className={[styles.detalles, className].filter(Boolean).join(' ')}>
      <summary>
        <Icono name="chevronDerecha" tam={12} className={styles.chevron} />
        {summary}
      </summary>
      {children}
    </details>
  )
}
