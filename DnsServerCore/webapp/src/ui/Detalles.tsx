import type { ReactNode } from 'react'
import { Icono } from './Icono'
import styles from './Detalles.module.css'

/** A `<details>` with the icon set's chevron. See the styles module. */
export function Detalles({
  resumen,
  children,
  className,
}: {
  resumen: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <details className={[styles.detalles, className].filter(Boolean).join(' ')}>
      <summary>
        <Icono nombre="chevronDerecha" tam={12} className={styles.chevron} />
        {resumen}
      </summary>
      {children}
    </details>
  )
}
