import type { ReactNode } from 'react'
import styles from './Alert.module.css'

/*
Réplica de `showAlert` de la consola antigua (common.js): un tipo, un título en
negrita, el texto a continuación y una «×» para descartarlo.

La «×» no es adorno: en upstream el aviso se puede cerrar, así que quitarla
sería quitar comportamiento. Se detectó comparando lado a lado contra la
instancia de referencia.
*/
export type AlertType = 'success' | 'info' | 'warning' | 'danger'

export function Alert({
  type,
  title,
  children,
  onDismiss,
}: {
  type: AlertType
  title: string
  children?: ReactNode
  onDismiss?: () => void
}) {
  return (
    <div className={`${styles.alert} ${styles[type]}`} role="alert">
      {onDismiss && (
        <button type="button" className={styles.close} aria-label="Close" onClick={onDismiss}>
          ×
        </button>
      )}
      <b>{title}</b> {children}
    </div>
  )
}
