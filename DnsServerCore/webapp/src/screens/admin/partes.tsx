import { Alert, type AlertType } from '../../ui/Alert'
import type { ClusterState } from '../../api/admin-cluster'
import styles from './Admin.module.css'
import frm from '../../ui/Form.module.css'
import { Select } from '../../ui/Select'
import { Row } from '../../ui/Form'
export { Check } from '../../ui/Check'

/* Las piezas que comparten las seis sub-pestañas de Administration. */

export interface Aviso {
  type: AlertType
  title: string
  text: string
}

/** `showAlert("danger", "Error!", …)`: upstream lo saca SIEMPRE que la
 *  respuesta no es `ok`, con el mensaje que manda el servidor. */
export function avisoDeFallo(outcome: { kind: string; message?: string }): Aviso {
  return {
    type: 'danger',
    title: 'Error!',
    text: outcome.kind === 'error' ? (outcome.message ?? 'Unknown error.') : 'Invalid token or session expired.',
  }
}

export function Avisador({ aviso, onCerrar }: { aviso: Aviso | null; onCerrar: () => void }) {
  if (aviso == null) return null
  return (
    <div className={styles.avisoHueco}>
      <Alert type={aviso.type} title={aviso.title} onDismiss={onCerrar}>
        {aviso.text}
      </Alert>
    </div>
  )
}


/*
`MRow` es la fila de `ui/Form` en su variante de modal. Era una tercera copia
—las otras dos vivían en las partes de Settings y de DHCP— y encima tenía un
fallo propio: usaba `frm.rowCtl` en vez de `frm.mrowCtl`, así que el control de
un modal de Administration se maquetaba con las reglas de una fila de página.
*/
export function MRow(props: Omit<Parameters<typeof Row>[0], 'modal'>) {
  return <Row {...props} modal />
}

/** Fila de sólo lectura: «Type» y «2FA Status» del modal de detalles. */
export function MValue({ label, value }: { label: string; value: string }) {
  return (
    <div className={frm.mrow}>
      <div className={frm.mrowLabel}>{label}</div>
      <div className={styles.mval}>{value}</div>
    </div>
  )
}


/*
`updateClusterNodeDropDown` (cluster.js:1026): el desplegable de nodos SÓLO
existe si el cluster está inicializado; si no, se oculta y su valor es la cadena
vacía. Cada opción se rotula «nombre (tipo en minúsculas)».
*/
export function SelectorNodo({
  cluster,
  value,
  onChange,
  label,
}: {
  cluster: ClusterState | null
  value: string
  onChange: (v: string) => void
  label: string
}) {
  if (!cluster?.clusterInitialized) return null
  const nodos = cluster.clusterNodes ?? []
  return (
    <Select
      className={styles.nodo}
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      {nodos.map((n) => (
        <option key={n.name} value={n.name}>
          {`${n.name} (${n.type.toLowerCase()})`}
        </option>
      ))}
    </Select>
  )
}


export { CeldaSesion } from '../../ui/Sesion'
export { Confirmar } from '../../ui/Confirmar'
export { styles as adminStyles }
