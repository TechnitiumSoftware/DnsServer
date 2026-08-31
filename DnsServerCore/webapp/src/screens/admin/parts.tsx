import type { ClusterState } from '../../api/admin-cluster'
import styles from './Admin.module.css'
import frm from '../../ui/Form.module.css'
import { Select } from '../../ui/Select'
import { Row } from '../../ui/Form'
export { Check } from '../../ui/Check'

/* The pieces Administration's six sub-tabs share. */

export type { Notice } from '../../lib/notice'
export { noticeFromFailure } from '../../lib/notice'



/*
`MRow` is `ui/Form`'s row in its modal variant. It was a third copy —the other
two lived in the Settings and DHCP parts— and on top of that it had a bug of its
own: it used `frm.rowCtl` instead of `frm.mrowCtl`, so an Administration modal's
control was laid out with the rules of a page row.
*/
export function MRow(props: Omit<Parameters<typeof Row>[0], 'modal'>) {
  return <Row {...props} modal />
}

/** Read-only row: the "Type" and "2FA Status" of the details modal. */
export function MValue({ label, value }: { label: string; value: string }) {
  return (
    <div className={frm.mrow}>
      <div className={frm.mrowLabel}>{label}</div>
      <div className={styles.mval}>{value}</div>
    </div>
  )
}


/*
`updateClusterNodeDropDown` (cluster.js:1026): the node dropdown ONLY exists if
the cluster is initialised; if not, it hides and its value is the empty string.
Each option is labelled "name (type lowercased)".
*/
export function NodePicker({
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
  const nodes = cluster.clusterNodes ?? []
  return (
    <Select
      className={styles.node}
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      {nodes.map((n) => (
        <option key={n.name} value={n.name}>
          {`${n.name} (${n.type.toLowerCase()})`}
        </option>
      ))}
    </Select>
  )
}


export { SessionCell } from '../../ui/SessionCells'
export { Confirm } from '../../ui/Confirm'
export { Notifier } from '../../ui/Notifier'
export { styles as adminStyles }
