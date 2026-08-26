import { useId, type ReactNode } from 'react'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Tag } from '../../ui/Tag'
import type { ClusterState } from '../../api/admin-cluster'
import styles from './Admin.module.css'

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
Los `confirm()` nativos de upstream. El texto y el paso son los mismos: sigue
haciendo falta confirmar antes de que salga la petición.
*/
export function Confirmar({
  abierto,
  titulo,
  texto,
  etiqueta,
  variante = 'danger',
  ocupado,
  onCerrar,
  onConfirmar,
}: {
  abierto: boolean
  titulo: string
  texto: ReactNode
  etiqueta: string
  variante?: 'primary' | 'danger'
  ocupado?: boolean
  onCerrar: () => void
  onConfirmar: () => void
}) {
  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={titulo}
      acciones={
        <>
          <Button variant={variante} disabled={ocupado} onClick={onConfirmar}>
            {etiqueta}
          </Button>
        </>
      }
      cerrar="Cancel"
    >
      <div className={styles.parrafo}>{texto}</div>
    </Dialog>
  )
}

/** Fila etiqueta + control, como en Settings pero con la etiqueta más estrecha
 *  para que quepa dentro de un modal. */
export function MRow({
  label,
  help,
  children,
}: {
  label: string
  help?: ReactNode
  children: (id: string) => ReactNode
}) {
  const id = useId()
  return (
    <div className={styles.mrow}>
      <label className={styles.mrowLabel} htmlFor={id}>
        {label}
      </label>
      <div className={styles.rowCtl}>
        {children(id)}
        {help && <div className={styles.help}>{help}</div>}
      </div>
    </div>
  )
}

/** Fila de sólo lectura: «Type» y «2FA Status» del modal de detalles. */
export function MValue({ label, value }: { label: string; value: string }) {
  return (
    <div className={styles.mrow}>
      <div className={styles.mrowLabel}>{label}</div>
      <div className={styles.mval}>{value}</div>
    </div>
  )
}

export function Check({
  label,
  checked,
  onChange,
  help,
  disabled,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
  help?: ReactNode
  disabled?: boolean
}) {
  return (
    <div>
      <label className={styles.check}>
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span>{label}</span>
      </label>
      {help && <div className={styles.checkHelp}>{help}</div>}
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
    <select
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
    </select>
  )
}

/*
La celda «Session», que sale idéntica en la pestaña Sessions y en el modal de
detalles del usuario (auth.js:876-899 y 1310-1333): el nombre del token si lo
tiene, el token parcial entre corchetes, «(current)» si es la sesión desde la
que se mira, y una etiqueta de color por tipo. Un tipo desconocido NO se calla:
sale como «Unknown» en ámbar.
*/
export function CeldaSesion({ sesion }: { sesion: { partialToken: string; tokenName: string | null; isCurrentSession: boolean; type: string } }) {
  const etiqueta =
    sesion.type === 'Standard' ? (
      <Tag>Standard</Tag>
    ) : sesion.type === 'ApiToken' ? (
      <Tag tone="info">API Token</Tag>
    ) : sesion.type === 'ClusterApiToken' ? (
      <Tag tone="info">Cluster API Token</Tag>
    ) : (
      <Tag tone="warn">Unknown</Tag>
    )

  return (
    <>
      {sesion.tokenName != null && <div>{sesion.tokenName}</div>}
      <div className={styles.mono}>{`[${sesion.partialToken}]`}</div>
      {sesion.isCurrentSession && <div>(current)</div>}
      <div style={{ marginTop: 4 }}>{etiqueta}</div>
    </>
  )
}

export { styles as adminStyles }
