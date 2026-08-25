import type { ReactNode } from 'react'
import styles from './Alert.module.css'

// Réplica de `showAlert` de la consola antigua (common.js): un tipo, un título
// en negrita y el texto a continuación. Los cuatro tipos son los de upstream.
export type AlertType = 'success' | 'info' | 'warning' | 'danger'

export function Alert({
  type,
  title,
  children,
}: {
  type: AlertType
  title: string
  children?: ReactNode
}) {
  return (
    <div className={`${styles.alert} ${styles[type]}`} role="alert">
      <b>{title}</b>
      {children}
    </div>
  )
}
