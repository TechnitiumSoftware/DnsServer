import { useEffect, useRef, useState } from 'react'
import { importZone } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { LabeledTextarea } from '../../../ui/Field'
import type { Notice } from '../tipos'
import styles from '../Zones.module.css'
import frm from '../../../ui/Form.module.css'
import { GroupRow, Row } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/aviso'
import { Notifier } from '../../../ui/Avisador'
import { Input } from '../../../ui/Field'

/*
`modalImportZone` (zone.js:1227 and 1251). Two ways of handing over the file
—uploading it or pasting it— and **the "file is missing" alert only exists in the
first**: if the text editor is empty, upstream sends the request all the same and
lets the server fail. It is replicated.
*/

type Mode = 'File' | 'Text'

export function ImportarZona({
  zone,
  open,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Notice) => void
}) {
  const [mode, setModo] = useState<Mode>('File')
  const [archivo, setArchivo] = useState<File | null>(null)
  const [text, setTexto] = useState('')
  const [overwrite, setOverwrite] = useState(true)
  const [overwriteZone, setOverwriteZone] = useState(false)
  const [overwriteSoaSerial, setOverwriteSoaSerial] = useState(false)
  const [notice, setAviso] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const fichero = useRef<HTMLInputElement>(null)

  // `showImportZoneModal`: on opening it returns to the defaults, which are NOT
  // son todos falsos — «Overwrite Existing Records» empieza marcado.
  useEffect(() => {
    if (!open) return
    setModo('File')
    setArchivo(null)
    setTexto('')
    setOverwrite(true)
    setOverwriteZone(false)
    setOverwriteSoaSerial(false)
    setAviso(null)
  }, [open])

  async function importar() {
    if (mode === 'File' && archivo == null) {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please select a zone file to import.' })
      fichero.current?.focus()
      return
    }

    setBusy(true)
    const outcome = await importZone(
      token,
      zone,
      mode === 'File' ? { archivo: archivo! } : { text },
      { overwrite, overwriteZone, overwriteSoaSerial },
      node,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Zone Imported!', text: 'The zone file was imported successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onCerrar()}
      size="medium"
      title={`Import - ${zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void importar()}>
            Import
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onCerrar={() => setAviso(null)} />

      <div className={styles.fields}>
        <GroupRow modal label="Import Options">
          <label className={styles.chk}>
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
            Overwrite Existing Records
          </label>
          <div className={styles.help}>
            Enable this option to overwrite existing records for the record types being imported.
          </div>
          <label className={styles.chk}>
            <input type="checkbox" checked={overwriteZone} onChange={(e) => setOverwriteZone(e.target.checked)} />
            Overwrite Zone
          </label>
          <div className={styles.help}>
            Enable this option to delete all existing records from the zone before importing new records.
          </div>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={overwriteSoaSerial}
              onChange={(e) => setOverwriteSoaSerial(e.target.checked)}
            />
            Overwrite SOA Serial
          </label>
          <div className={styles.help}>
            Enable this option to overwrite existing SOA record serial with the imported SOA record serial.
          </div>
        </GroupRow>

        <GroupRow modal label="Import Type">
          <label className={styles.chk}>
            <input
              type="radio"
              name="importType"
              checked={mode === 'File'}
              onChange={() => setModo('File')}
            />
            Zone File
          </label>
          <label className={styles.chk}>
            <input
              type="radio"
              name="importType"
              checked={mode === 'Text'}
              onChange={() => setModo('Text')}
            />
            Text Editor
          </label>
        </GroupRow>

        {mode === 'File' ? (
          <Row modal label="Zone File">
            {(id) => (
              <Input
                id={id}
                ref={fichero}
                type="file"
                onChange={(e) => setArchivo(e.target.files?.[0] ?? null)}
              />
            )}
          </Row>
        ) : (
          <div className={frm.mrowCtl}>
            <LabeledTextarea
              label="Text Editor"
              mono
              className={styles.areaAlta}
              spellCheck={false}
              value={text}
              onChange={(e) => setTexto(e.target.value)}
            />
            <div className={styles.help}>
              Enter the records to be imported above in standard zone file format.
            </div>
          </div>
        )}

        <Alert type="info" title="Note!">
          The $ORIGIN and $TTL values will be automatically set if not specified.
        </Alert>
        <Alert type="warning" title="Warning!">
          Overwrite SOA serial option when used to set a lower SOA serial value than the
          current SOA serial will cause secondary zones to fail to sync.
        </Alert>
      </div>
    </Dialog>
  )
}
