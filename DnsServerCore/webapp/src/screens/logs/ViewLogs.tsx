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
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import {Empty, Loading} from '../../ui/Empty'
import styles from './Logs.module.css'

/*
Logs › View Logs (logs.js:105-268).

Cuatro cosas de upstream que gobiernan esta pantalla:

  1. **Las tres acciones de borrado NO son de la misma sección.** «delete all
     logs» y borrar un fichero piden `Logs.Delete`; «delete all stats» borra las
     estadísticas del Dashboard y pide `Dashboard.Delete`
     (`WebServiceLogsApi.cs:107,123,135`). Están juntas en la pantalla y son
     permisos distintos.
  2. **«delete all stats» se ofrece SIEMPRE; «delete all logs» sólo si hay
     ficheros** (logs.js:119-127). Sin ficheros sale «No Log File Was Found».
  3. **El visor pide sólo 2 MB** y el botón «Download» el fichero entero; son
     dos llamadas distintas al mismo endpoint.
  4. **Un error del servidor se pinta DENTRO del visor**, formateado como JSON,
     en vez de como aviso (logs.js:170-172). No es un descuido: el endpoint
     devuelve texto y la única forma de enseñar el error es en el mismo hueco.
*/

interface Aviso { type: AlertType; title: string; text: string }

export interface ViewLogsProps {
  token: string | null
  node?: string
  /** `Logs.canDelete`: borrar un log y borrarlos todos. */
  canDeleteLogs?: boolean
  /** `Dashboard.canDelete`: borrar todas las estadísticas. */
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

  // Un fallo al cargar no se pinta como lista vacía; ver `dhcp/Leases`.
  const cargar = useCallback(async () => {
    const r = await listLogFiles(token, node)
    if (r.kind === 'ok') {
      setFicheros(r.data)
      return
    }
    setFicheros([])
    setAviso({
      type: 'danger',
      title: 'Error!',
      text: r.kind === 'error' ? r.message : 'Invalid token or session expired.',
    })
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
        acciones={<>{/* logs.js:121 — «delete all logs» sólo existe si hay ficheros. */}
          {canDeleteLogs && ficheros.length > 0 && (
            <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('allLogs')}>
              Delete All Logs
            </Button>
          )}
          {/* logs.js:117 — «delete all stats» se ofrece siempre. */}
          {canDeleteStats && (
            <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('allStats')}>
              Delete All Stats
            </Button>
          )}</>}
      />

      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

      <div className={styles.dos}>
        <div className={styles.panel}>
          <div className={styles.ph}>
            <h2>Log Files</h2>
          </div>
          <div className={styles.pbLista}>
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
          </div>
        </div>

        {abierto != null && (
          <div className={styles.panel}>
            <div className={styles.ph}>
              <h2>
                <span className={styles.mono}>{abierto}</span>
              </h2>
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
            </div>
            <div className={styles.pb}>
              {cargandoCuerpo ? (
                <Loading />
              ) : (
                <pre className={styles.out}>{cuerpo ?? ''}</pre>
              )}
            </div>
          </div>
        )}
      </div>

      <Dialog
        open={confirmar !== null}
        onOpenChange={(o) => !o && setConfirmar(null)}
        title={confirmar ? TEXTO_CONFIRM[confirmar].titulo : ''}
        acciones={
          <>
            <Button
              variant="danger"
              disabled={ocupado}
              onClick={() => {
                if (confirmar === 'log') void borrarLog()
                else if (confirmar === 'allLogs') void borrarTodos()
                else if (confirmar === 'allStats') void borrarStats()
              }}
            >
              {confirmar ? TEXTO_CONFIRM[confirmar].etiqueta : ''}
            </Button>
          </>
        }
        cerrar="Cancel"
        tamano="compacto"
      >
        <p className={styles.parrafo}>{confirmar ? TEXTO_CONFIRM[confirmar].texto : ''}</p>
      </Dialog>
    </div>
  )
}
