import { useEffect, useRef, type ReactNode } from 'react'
import { Icon } from './Icon'
import styles from './Alert.module.css'

/*
A replica of the old console's `showAlert` (common.js:202-217): a type, a bold
title, the text after it and a "×" to dismiss it.

The "×" is not decoration: in upstream the alert can be closed, so removing it
would be removing behaviour. It was caught by comparing side by side against the
reference instance.

And **success alerts dismiss themselves after five seconds**, as they do there
(`common.js:213-217`, `success` only). It was missing: it was a real behavioural
difference, and a noticeable one, because a "Settings Saved!" that never goes away
ends up covering the next alert.
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
  // The dismiss callback is kept in a ref: the places that pass it write a new
  // function on every render, and as a dependency it would restart the timer
  // forever and never fire.
  const dismiss = useRef(onDismiss)
  dismiss.current = onDismiss

  useEffect(() => {
    if (type !== 'success' || onDismiss == null) return
    const t = setTimeout(() => dismiss.current?.(), AUTO_DESCARTE_MS)
    return () => clearTimeout(t)
    // The timer restarts with each new alert, even if the previous one was also
    // a success: that is what upstream does, since it rebuilds the whole node.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, title, children])

  return (
    <div className={`${styles.alert} ${styles[type]}`} role="alert">
      {onDismiss && (
        <button type="button" className={styles.close} aria-label="Close" onClick={onDismiss}>
          <Icon name="close" tam={14} />
        </button>
      )}
      <b>{title}</b> {children}
    </div>
  )
}
