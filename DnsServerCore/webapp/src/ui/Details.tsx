import type { ReactNode } from 'react'
import { Icon } from './Icon'
import styles from './Details.module.css'

/** A `<details>` with the icon set's chevron. See the styles module. */
export function Details({
  summary,
  children,
  className,
}: {
  summary: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <details className={[styles.details, className].filter(Boolean).join(' ')}>
      <summary>
        <Icon name="chevronRight" size={12} className={styles.chevron} />
        {summary}
      </summary>
      {children}
    </details>
  )
}
