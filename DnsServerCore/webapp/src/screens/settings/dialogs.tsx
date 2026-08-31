import { useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Alert } from '../../ui/Alert'
import { Field } from '../../ui/Field'
import styles from './Settings.module.css'
import { ELEMENTOS_BACKUP } from '../../api/settings'
import { Check } from './parts'
import { Input } from '../../ui/Field'

/*
The "are you sure?" step is `ui/Confirmar`, the same dialog the other five
screens use. It is re-exported under the name it is asked for by here.
*/
export { Confirm } from '../../ui/Confirm'

function ItemList({
  selection,
  onChange,
  prefix,
}: {
  selection: Record<string, boolean>
  onChange: (s: Record<string, boolean>) => void
  prefix: string
}) {
  return (
    <div className={styles.group}>
      {ELEMENTOS_BACKUP.map((e) => (
        <Check
          key={`${prefix}-${e.key}`}
          label={e.label}
          checked={selection[e.key] === true}
          onChange={(v) => onChange({ ...selection, [e.key]: v })}
        />
      ))}
    </div>
  )
}

export interface DialogoProps {
  open: boolean
  onOpenChange: (o: boolean) => void
  selection: Record<string, boolean>
  onSelection: (s: Record<string, boolean>) => void
  notice: { title: string; text: string } | null
  busy?: boolean
}

/** Modal «Backup Settings» (index.html:6283-6380). */
export function BackupDialog({
  open,
  onOpenChange,
  selection,
  onSelection,
  notice,
  busy,
  onBackup,
}: DialogoProps & { onBackup: () => void }) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Backup Settings"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={onBackup}>
            Backup
          </Button>
        </>
      }
    >
      {notice && (
        <Alert type="warning" title={notice.title}>
          {notice.text}
        </Alert>
      )}
      <p>The backup process will create a zip file for the items selected below:</p>
      <ItemList selection={selection} onChange={onSelection} prefix="backup" />
      <div className={styles.notas}>
        <Alert type="info" title="Note!">
          The Web Service or Optional Protocols TLS certificate (.pfx or .p12) files will be
          included in the backup only if they exist within the DNS Server's config folder.
        </Alert>
        <Alert type="info" title="Note!">
          It may take several minutes to generate the backup zip file if log files are selected to
          be backed up which will depend on the size of the log files on the disk.
        </Alert>
      </div>
    </Dialog>
  )
}

/** Modal «Restore Settings» (index.html:6392-6512). */
export function RestoreDialog({
  open,
  onOpenChange,
  selection,
  onSelection,
  notice,
  busy,
  onRestore,
}: DialogoProps & { onRestore: (file: File | null, remove: boolean) => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [remove, setDelete] = useState(true)

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Restore Settings"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => onRestore(file, remove)}>
            Restore
          </Button>
        </>
      }
    >
      {notice && (
        <Alert type="warning" title={notice.title}>
          {notice.text}
        </Alert>
      )}
      <Field label="Backup Zip File">
        {(id) => (
          <Input id={id} type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        )}
      </Field>
      <p>The restore process will restore all the selected items from the backup zip file:</p>
      <ItemList selection={selection} onChange={onSelection} prefix="restore" />
      <p>Restore options:</p>
      <Check
        label="Delete Existing Files For Selected Items"
        checked={remove}
        onChange={setDelete}
      />
      <div>
        <Alert type="warning" title="Warning!">
          The restore process will overwrite existing config files on disk for above selected items
          and reload new settings including user accounts from the backup. The current logged in
          user account and current session will be added automatically.
        </Alert>
      </div>
    </Dialog>
  )
}
