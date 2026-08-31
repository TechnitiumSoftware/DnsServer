import { useCallback, useEffect, useState } from 'react'
import {
  deleteAllLogs,
  deleteLog,
  downloadLogText,
  listLogFiles,
  openLogDownload,
  type LogFile,
} from '../../api/logs'
import { deleteAllStats } from '../../api/dashboard'
import { Confirmar } from '../../ui/Confirmar'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import {Empty, Loading} from '../../ui/Empty'
import styles from './Logs.module.css'
import { Cuerpo, Panel } from '../../ui/Panel'
import { avisoDeFallo, type Aviso } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'

/*
Logs › View Logs (logs.js:105-268).

Four things from upstream that govern this screen:

  1. **The three delete actions are NOT of the same section.** "delete all logs"
     and deleting a file ask for `Logs.Delete`; "delete all stats" deletes the
     Dashboard's statistics and asks for `Dashboard.Delete`
     (`WebServiceLogsApi.cs:107,123,135`). They sit together on the screen and
     they are different permissions.
  2. **"delete all stats" is ALWAYS offered; "delete all logs" only if there are
     files** (logs.js:119-127). With no files it says "No Log File Was Found".
  3. **The viewer asks for only 2 MB** and the "Download" button for the whole
     file; they are two different calls to the same endpoint.
  4. **A server error is drawn INSIDE the viewer**, formatted as JSON, instead of
     as an alert (logs.js:170-172). It is not an oversight: the endpoint returns
     text and the only way to show the error is in that same space.
*/


export interface ViewLogsProps {
  token: string | null
  node?: string
  /** `Logs.canDelete`: borrar un log y borrarlos todos. */
  canDeleteLogs?: boolean
  /** `Dashboard.canDelete`: deleting all the statistics. */
  canDeleteStats?: boolean
}

type Confirmacion = 'log' | 'allLogs' | 'allStats'

export function ViewLogs({
  token,
  node = '',
  canDeleteLogs = true,
  canDeleteStats = true,
}: ViewLogsProps) {
  const [ficheros, setFicheros] = useState<LogFile[] | null>(null)
  const [abierto, setAbierto] = useState<string | null>(null)
  const [cuerpo, setCuerpo] = useState<string | null>(null)
  const [cargandoCuerpo, setCargandoCuerpo] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [confirmar, setConfirmar] = useState<Confirmacion | null>(null)

  // A failure on load is not drawn as an empty list; see `dhcp/Leases`.
  const cargar = useCallback(async () => {
    const r = await listLogFiles(token, node)
    if (r.kind === 'ok') {
      setFicheros(r.data)
      return
    }
    setFicheros([])
    setAviso(avisoDeFallo(r))
  }, [token, node])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function ver(fileName: string) {
    setAbierto(fileName)
    setCuerpo(null)
    setCargandoCuerpo(true)
    const texto = await downloadLogText(token, fileName, node)
    setCargandoCuerpo(false)
    setCuerpo(texto)
  }

  async function descargar() {
    if (abierto == null) return
    setOcupado(true)
    await openLogDownload(token, abierto, node)
    setOcupado(false)
  }

  async function borrarLog() {
    if (abierto == null) return
    setConfirmar(null)
    setOcupado(true)
    const outcome = await deleteLog(token, abierto, node)
    setOcupado(false)
    if (outcome.kind !== 'ok') return

    await cargar()
    setAbierto(null)
    setCuerpo(null)
    setAviso({
      type: 'success',
      title: 'Log Deleted!',
      text: 'Log file was deleted successfully.',
    })
  }

  async function borrarTodos() {
    setConfirmar(null)
    setOcupado(true)
    const outcome = await deleteAllLogs(token, node)
    setOcupado(false)
    if (outcome.kind !== 'ok') return

    await cargar()
    setAbierto(null)
    setCuerpo(null)
    setAviso({
      type: 'success',
      title: 'Logs Deleted!',
      text: 'All log files were deleted successfully.',
    })
  }

  async function borrarStats() {
    setConfirmar(null)
    setOcupado(true)
    const outcome = await deleteAllStats(token)
    setOcupado(false)
    if (outcome.kind !== 'ok') return

    setAviso({
      type: 'success',
      title: 'Stats Deleted!',
      text: 'All stats files were deleted successfully.',
    })
  }

  if (ficheros == null) return <Loading />

  const TEXTO_CONFIRM: Record<Confirmacion, { titulo: string; texto: string; etiqueta: string }> = {
    log: {
      titulo: 'Delete Log',
      texto: `Are you sure you want to permanently delete the log file '${abierto ?? ''}'?`,
      etiqueta: 'Delete',
    },
    allLogs: {
      titulo: 'Delete All Logs',
      texto: 'Are you sure you want to permanently delete all log files?',
      etiqueta: 'Delete All Logs',
    },
    allStats: {
      titulo: 'Delete All Stats',
      texto: 'Are you sure you want to permanently delete all stats files?',
      etiqueta: 'Delete All Stats',
    },
  }

  return (
    <div className={styles.wrap}>
      <SectionHeader
        seccion="Logs"
        titulo="View Logs"
        acciones={<>{/* logs.js:121 — "delete all logs" only exists if there are files. */}
          {canDeleteLogs && ficheros.length > 0 && (
            <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('allLogs')}>
              Delete All Logs
            </Button>
          )}
          {/* logs.js:117 — "delete all stats" is always offered. */}
          {canDeleteStats && (
            <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('allStats')}>
              Delete All Stats
            </Button>
          )}</>}
      />

      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      <div className={styles.dos}>
        <Panel titulo="Log Files" className={styles.panel}>
          <Cuerpo className={styles.pbLista}>
            {ficheros.length === 0 ? (
              <Empty>
                {aviso?.type === 'danger'
                  ? 'Unable to load the log files.'
                  : 'No Log File Was Found'}
              </Empty>
            ) : (
              <div className={styles.logfiles}>
                {ficheros.map((f) => (
                  <button
                    key={f.fileName}
                    type="button"
                    className={styles.logfile}
                    aria-current={abierto === f.fileName}
                    onClick={() => void ver(f.fileName)}
                  >
                    <span className={styles.nombre}>{f.fileName}</span>
                    <span className={styles.sz}>[{f.size}]</span>
                  </button>
                ))}
              </div>
            )}
          </Cuerpo>
        </Panel>

        {abierto != null && (
          <Panel
            className={styles.panel}
            titulo={<span className={styles.mono}>{abierto}</span>}
            acciones={
              <div className={styles.acts}>
                <Button disabled={ocupado} onClick={() => void descargar()}>
                  Download
                </Button>
                {canDeleteLogs && (
                  <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('log')}>
                    Delete
                  </Button>
                )}
              </div>
            }
          >
            <Cuerpo>
              {cargandoCuerpo ? (
                <Loading />
              ) : (
                <pre className={styles.out}>{cuerpo ?? ''}</pre>
              )}
            </Cuerpo>
          </Panel>
        )}
      </div>

      <Confirmar
        abierto={confirmar !== null}
        titulo={confirmar ? TEXTO_CONFIRM[confirmar].titulo : ''}
        texto={confirmar ? TEXTO_CONFIRM[confirmar].texto : ''}
        etiqueta={confirmar ? TEXTO_CONFIRM[confirmar].etiqueta : ''}
        ocupado={ocupado}
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => {
          if (confirmar === 'log') void borrarLog()
          else if (confirmar === 'allLogs') void borrarTodos()
          else if (confirmar === 'allStats') void borrarStats()
        }}
      />
    </div>
  )
}
