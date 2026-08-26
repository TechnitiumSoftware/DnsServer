import { useEffect, useRef, useState } from 'react'
import { importZone } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { LabeledTextarea } from '../../../ui/Field'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'

/*
`modalImportZone` (zone.js:1227 y 1251). Dos formas de dar el fichero —subirlo
o pegarlo— y **el aviso de que falta el fichero sólo existe en la primera**: si
el editor de texto está vacío, upstream manda la petición igual y deja que
falle el servidor. Se replica.
*/

type Modo = 'File' | 'Text'

export function ImportarZona({
  zone,
  abierto,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const [modo, setModo] = useState<Modo>('File')
  const [archivo, setArchivo] = useState<File | null>(null)
  const [texto, setTexto] = useState('')
  const [overwrite, setOverwrite] = useState(true)
  const [overwriteZone, setOverwriteZone] = useState(false)
  const [overwriteSoaSerial, setOverwriteSoaSerial] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const fichero = useRef<HTMLInputElement>(null)

  // `showImportZoneModal`: al abrir vuelve a los valores por defecto, que NO
  // son todos falsos — «Overwrite Existing Records» empieza marcado.
  useEffect(() => {
    if (!abierto) return
    setModo('File')
    setArchivo(null)
    setTexto('')
    setOverwrite(true)
    setOverwriteZone(false)
    setOverwriteSoaSerial(false)
    setAviso(null)
  }, [abierto])

  async function importar() {
    if (modo === 'File' && archivo == null) {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please select a zone file to import.' })
      fichero.current?.focus()
      return
    }

    setOcupado(true)
    const outcome = await importZone(
      token,
      zone,
      modo === 'File' ? { archivo: archivo! } : { texto },
      { overwrite, overwriteZone, overwriteSoaSerial },
      node,
    )
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Zone Imported!', text: 'The zone file was imported successfully.' })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Import - ${zone}`}
      footer={
        <>
          <Button onClick={onCerrar}>Close</Button>
          <Button variant="primary" disabled={ocupado} onClick={() => void importar()}>
            Import
          </Button>
        </>
      }
    >
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

      <div className={styles.campos}>
        <div className={styles.fila}>
          <div className={styles.filaLab}>Import Options</div>
          <div className={styles.filaCtl}>
            <label className={styles.chk}>
              <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
              Overwrite Existing Records
            </label>
            <div className={styles.ayuda}>
              Enable this option to overwrite existing records for the record types being imported.
            </div>
            <label className={styles.chk}>
              <input type="checkbox" checked={overwriteZone} onChange={(e) => setOverwriteZone(e.target.checked)} />
              Overwrite Zone
            </label>
            <div className={styles.ayuda}>
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
            <div className={styles.ayuda}>
              Enable this option to overwrite existing SOA record serial with the imported SOA record serial.
            </div>
          </div>
        </div>

        <div className={styles.fila}>
          <div className={styles.filaLab}>Import Type</div>
          <div className={styles.filaCtl}>
            <label className={styles.chk}>
              <input
                type="radio"
                name="importType"
                checked={modo === 'File'}
                onChange={() => setModo('File')}
              />
              Zone File
            </label>
            <label className={styles.chk}>
              <input
                type="radio"
                name="importType"
                checked={modo === 'Text'}
                onChange={() => setModo('Text')}
              />
              Text Editor
            </label>
          </div>
        </div>

        {modo === 'File' ? (
          <div className={styles.fila}>
            <div className={styles.filaLab}>
              <label htmlFor="fileImportZone">Zone File</label>
            </div>
            <div className={styles.filaCtl}>
              <input
                id="fileImportZone"
                ref={fichero}
                type="file"
                onChange={(e) => setArchivo(e.target.files?.[0] ?? null)}
              />
            </div>
          </div>
        ) : (
          <div className={styles.filaCtl}>
            <LabeledTextarea
              label="Text Editor"
              mono
              className={styles.areaAlta}
              spellCheck={false}
              value={texto}
              onChange={(e) => setTexto(e.target.value)}
            />
            <div className={styles.ayuda}>
              Enter the records to be imported above in standard zone file format.
            </div>
          </div>
        )}

        <div className={`${styles.nota} ${styles.notaInfo}`}>
          <b>Note!</b> The $ORIGIN and $TTL values will be automatically set if not specified.
        </div>
        <div className={`${styles.nota} ${styles.notaAviso}`}>
          <b>Warning!</b> Overwrite SOA serial option when used to set a lower SOA serial value than the
          current SOA serial will cause secondary zones to fail to sync.
        </div>
      </div>
    </Dialog>
  )
}
