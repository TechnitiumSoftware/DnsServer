import { useEffect, useRef, type ReactNode } from 'react'
import styles from './Alert.module.css'

/*
Réplica de `showAlert` de la consola antigua (common.js:202-217): un tipo, un
título en negrita, el texto a continuación y una «×» para descartarlo.

La «×» no es adorno: en upstream el aviso se puede cerrar, así que quitarla
sería quitar comportamiento. Se detectó comparando lado a lado contra la
instancia de referencia.

Y **los avisos de éxito se van solos a los cinco segundos**, como allí
(`common.js:213-217`, sólo los `success`). Faltaba: era una diferencia real de
comportamiento, y de las que se notan, porque un «Settings Saved!» que no se va
nunca acaba tapando el siguiente aviso.
*/
export type AlertType = 'success' | 'info' | 'warning' | 'danger'

const AUTO_DESCARTE_MS = 5000

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
  // El descarte se guarda en una ref: los sitios que lo pasan escriben una
  // función nueva en cada render, y como dependencia reiniciaría el reloj
  // eternamente y no saltaría nunca.
  const descartar = useRef(onDismiss)
  descartar.current = onDismiss

  useEffect(() => {
    if (type !== 'success' || onDismiss == null) return
    const t = setTimeout(() => descartar.current?.(), AUTO_DESCARTE_MS)
    return () => clearTimeout(t)
    // El reloj arranca de nuevo con cada aviso nuevo, aunque el anterior fuera
    // también un éxito: es lo que hace upstream, que rehace el nodo entero.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, title, children])

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
