import { useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Alert } from '../../ui/Alert'
import { Field } from '../../ui/Field'
import styles from './Settings.module.css'
import { ELEMENTOS_BACKUP } from '../../api/settings'
import { Check } from './parts'

/*
Los tres diálogos de la barra de acciones.

`Confirm` sustituye a los `confirm()` nativos de upstream (main.js:2347, 2382 y
other-zones.js:21). El texto es el mismo y el paso es el mismo: sigue haciendo
falta confirmar antes de que salga la petición.

El botón lleva el VERBO, no «OK». Lo llevaba, y era el único sitio de la consola
donde no: las otras siete confirmaciones —Zones, Listas, ViewLogs, DHCP y las de
Administration— dicen «Flush», «Disable», «Delete». Contra upstream las dos formas
valen, porque su `confirm()` nativo siempre dice OK; entre ellas, no.
*/
export function Confirm({
  open,
  onOpenChange,
  title,
  texto,
  etiqueta,
  onConfirm,
  ocupado,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  title: string
  texto: string
  /** El verbo de la acción. */
  etiqueta: string
  onConfirm: () => void
  ocupado?: boolean
}) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={onConfirm}>
            {etiqueta}
          </Button>
        </>
      }
      cerrar="Cancel"
    >
      {texto}
    </Dialog>
  )
}

function ListaElementos({
  seleccion,
  onChange,
  prefijo,
}: {
  seleccion: Record<string, boolean>
  onChange: (s: Record<string, boolean>) => void
  prefijo: string
}) {
  return (
    <div className={styles.group}>
      {ELEMENTOS_BACKUP.map((e) => (
        <Check
          key={`${prefijo}-${e.key}`}
          label={e.label}
          checked={seleccion[e.key] === true}
          onChange={(v) => onChange({ ...seleccion, [e.key]: v })}
        />
      ))}
    </div>
  )
}

export interface DialogoProps {
  open: boolean
  onOpenChange: (o: boolean) => void
  seleccion: Record<string, boolean>
  onSeleccion: (s: Record<string, boolean>) => void
  aviso: { title: string; text: string } | null
  ocupado?: boolean
}

/** Modal «Backup Settings» (index.html:6283-6380). */
export function BackupDialog({
  open,
  onOpenChange,
  seleccion,
  onSeleccion,
  aviso,
  ocupado,
  onBackup,
}: DialogoProps & { onBackup: () => void }) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Backup Settings"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={onBackup}>
            Backup
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type="warning" title={aviso.title}>
          {aviso.text}
        </Alert>
      )}
      <p>The backup process will create a zip file for the items selected below:</p>
      <ListaElementos seleccion={seleccion} onChange={onSeleccion} prefijo="backup" />
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
  seleccion,
  onSeleccion,
  aviso,
  ocupado,
  onRestore,
}: DialogoProps & { onRestore: (fichero: File | null, borrar: boolean) => void }) {
  const [fichero, setFichero] = useState<File | null>(null)
  const [borrar, setBorrar] = useState(true)

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Restore Settings"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => onRestore(fichero, borrar)}>
            Restore
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type="warning" title={aviso.title}>
          {aviso.text}
        </Alert>
      )}
      <Field label="Backup Zip File">
        {(id) => (
          <input id={id} type="file" onChange={(e) => setFichero(e.target.files?.[0] ?? null)} />
        )}
      </Field>
      <p>The restore process will restore all the selected items from the backup zip file:</p>
      <ListaElementos seleccion={seleccion} onChange={onSeleccion} prefijo="restore" />
      <p>Restore options:</p>
      <Check
        label="Delete Existing Files For Selected Items"
        checked={borrar}
        onChange={setBorrar}
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
