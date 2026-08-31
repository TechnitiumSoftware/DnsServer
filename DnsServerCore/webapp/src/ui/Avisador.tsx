import { Alert } from './Alert'
import type { Aviso } from '../lib/aviso'
import styles from './Alert.module.css'

/*
The alert slot of a screen or a modal: if there is an alert, it is painted; if
not, there is nothing. And always with the same air beneath it.

It existed as a component inside Administration and ONE screen used it; the other
fifty wrote the same `{aviso && (<Alert …>{aviso.text}</Alert>)}` by hand. Out of
that came three different distances for the same thing, measured in the browser by
forcing a server failure:

  · 24 px in Zones, its twelve modals, the lists screens, Administration, the
    Dashboard, DNS Client and Apps, which wrapped the alert in a `div` with a
    margin;
  · 14 px in DHCP and in Logs, where the alert sat loose inside the screen's
    `flex` container and kept its `gap`;
  · 12 px in the four account modals, for the same reason inside the dialog.

It settles at 24, which is `--hueco-bloque` —the token that names the distance
between independent blocks— and the one three quarters of them already had.
*/
export function Avisador({ aviso, onCerrar }: { aviso: Aviso | null; onCerrar: () => void }) {
  if (aviso == null) return null
  return (
    <div className={styles.gap}>
      <Alert type={aviso.type} title={aviso.title} onDismiss={onCerrar}>
        {aviso.text}
      </Alert>
    </div>
  )
}
