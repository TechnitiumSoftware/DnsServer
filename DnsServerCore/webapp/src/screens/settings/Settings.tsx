import { useCallback, useEffect, useState } from 'react'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { openDownload } from '../../api/user'
import {
  flushCache,
  forceUpdateBlockLists,
  getSettings,
  parametrosBackup,
  restoreSettings,
  seleccionInicialBackup,
  setSettings,
  temporaryDisableBlocking,
  type DnsSettings,
} from '../../api/settings'
import { construirCuerpo, formularioDesdeAjustes, habilitado, type SettingsForm } from './model'
import { General } from './panes/General'
import { WebService } from './panes/WebService'
import { OptionalProtocols } from './panes/OptionalProtocols'
import { Tsig } from './panes/Tsig'
import { Recursion } from './panes/Recursion'
import { Cache } from './panes/Cache'
import { Blocking } from './panes/Blocking'
import { ProxyForwarders } from './panes/ProxyForwarders'
import { Logging } from './panes/Logging'
import { BackupDialog, Confirm, RestoreDialog } from './dialogs'
import { Loading } from '../../ui/Empty'
import styles from './Settings.module.css'

/*
Settings. La pantalla más grande de la consola: en upstream, sólo la sub-pestaña
General mide 5.452 px de alto.

La sub-navegación NO se monta aquí. Las nueve sub-pestañas viven en el panel
lateral del Shell, anidadas bajo Settings, y llegan por la prop `sub`. Este
componente sólo decide qué panel pinta y mantiene UN ÚNICO estado de formulario
para las nueve: upstream tampoco tiene nueve formularios, tiene uno solo con
nueve pestañas, y «Save Settings» manda SIEMPRE los campos de las nueve estés
donde estés. Trocearlo por pestaña cambiaría lo que se guarda.

Dos consecuencias de eso que hay que tener presentes:

  · Un fallo de validación puede estar en otra sub-pestaña. Upstream le da el
    foco al campo aunque su pestaña esté oculta y el usuario no ve nada. Aquí el
    aviso dice qué falta y la pantalla salta a la sub-pestaña del campo.
  · Los tres permisos de la barra son distintos: guardar exige
    `Settings.canModify`, vaciar la caché `Cache.canDelete`, y copia y
    restauración `Settings.canDelete` (main.js:906-930).
*/

export const SUBPESTANAS = [
  'General',
  'Web Service',
  'Optional Protocols',
  'TSIG',
  'Recursion',
  'Cache',
  'Blocking',
  'Proxy & Forwarders',
  'Logging',
] as const

export type Subpestana = (typeof SUBPESTANAS)[number]

interface AvisoState { type: AlertType; title: string; text: string }

export interface SettingsProps {
  token: string | null
  /** Sub-pestaña activa, la que marca el panel lateral del Shell. */
  sub?: string | null
  /** Permite al Shell seguir a la pantalla cuando un fallo de validación la
   *  obliga a saltar a otra sub-pestaña. */
  onSubChange?: (sub: Subpestana) => void
  canModify?: boolean
  canFlushCache?: boolean
  canBackup?: boolean
}

export function Settings({
  token,
  sub,
  onSubChange,
  canModify = true,
  canFlushCache = true,
  canBackup = true,
}: SettingsProps) {
  const [ajustes, setAjustes] = useState<DnsSettings | null>(null)
  const [form, setForm] = useState<SettingsForm | null>(null)
  const [cargando, setCargando] = useState(true)
  const [ocupado, setOcupado] = useState(false)
  const [aviso, setAviso] = useState<AvisoState | null>(null)
  // El salto por validación recuerda desde qué sub-pestaña se disparó: en cuanto
  // el Shell pide otra distinta, deja de valer. Derivarlo así evita un efecto
  // que sólo servía para ponerlo a null y el render de más que trae consigo.
  const [salto, setSalto] = useState<{ tab: Subpestana; desde: string } | null>(null)
  const [confirmar, setConfirmar] = useState<null | 'flush' | 'disable' | 'update'>(null)
  const [modal, setModal] = useState<null | 'backup' | 'restore'>(null)
  const [seleccion, setSeleccion] = useState<Record<string, boolean>>(seleccionInicialBackup)
  const [avisoModal, setAvisoModal] = useState<{ title: string; text: string } | null>(null)
  const [proximaLista, setProximaLista] = useState<string | null | undefined>(undefined)

  const cargar = useCallback(async () => {
    setCargando(true)
    const s = await getSettings(token)
    aplicar(s)
    setCargando(false)
  }, [token])

  function aplicar(s: DnsSettings | null) {
    setAjustes(s)
    setForm(s ? formularioDesdeAjustes(s) : null)
    setProximaLista(s?.blockListNextUpdatedOn)
  }

  useEffect(() => {
    void cargar()
  }, [cargar])

  const pedida = (sub ?? 'General') as Subpestana
  const valida: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'General'
  const activa: Subpestana = salto?.desde === valida ? salto.tab : valida

  const set = useCallback((parcial: Partial<SettingsForm>) => {
    setForm((f) => (f ? { ...f, ...parcial } : f))
  }, [])

  if (cargando) return <Loading />
  if (form == null || ajustes == null) {
    return <div className={styles.fail}>Unable to load the DNS Server settings.</div>
  }

  const en = habilitado(form)

  async function guardar() {
    if (form == null) return
    const resultado = construirCuerpo(form)

    if (resultado.error) {
      const { title, text, tab } = resultado.error
      setAviso({ type: 'warning', title, text })
      const destino = tab as Subpestana
      setSalto({ tab: destino, desde: valida })
      onSubChange?.(destino)
      return
    }

    setOcupado(true)
    const outcome = await setSettings(token, resultado.body!)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    aplicar(outcome.data.response)
    setAviso({
      type: 'success',
      title: 'Settings Saved!',
      text: 'DNS Server settings were saved successfully.',
    })
  }

  async function vaciarCache() {
    setConfirmar(null)
    setOcupado(true)
    const ok = await flushCache(token)
    setOcupado(false)
    if (ok) {
      setAviso({
        type: 'success',
        title: 'Flushed!',
        text: 'DNS Server cache was flushed successfully.',
      })
    }
  }

  function pedirDesactivarBloqueo() {
    if (form == null) return
    if (form.temporaryDisableBlockingMinutes === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value in minutes to temporarily disable blocking.',
      })
      return
    }
    setConfirmar('disable')
  }

  async function desactivarBloqueo() {
    if (form == null) return
    const minutos = form.temporaryDisableBlockingMinutes
    setConfirmar(null)
    setOcupado(true)
    const till = await temporaryDisableBlocking(token, minutos)
    setOcupado(false)
    if (till == null) return

    setAjustes((a) => (a ? { ...a, temporaryDisableBlockingTill: till } : a))
    set({ enableBlocking: false })
    setAviso({
      type: 'success',
      title: 'Blocking Disabled!',
      text: `Blocking was successfully disabled temporarily for ${minutos} minute(s).`,
    })
  }

  async function actualizarListas() {
    setConfirmar(null)
    setOcupado(true)
    const ok = await forceUpdateBlockLists(token)
    setOcupado(false)
    if (!ok) return
    // main.js:2356 — la etiqueta pasa a «Updating Now» sin recargar los ajustes.
    setProximaLista(new Date(0).toISOString())
    setAviso({
      type: 'success',
      title: 'Updating Block List!',
      text: 'Block list update was triggered successfully.',
    })
  }

  async function hacerBackup() {
    if (!Object.values(seleccion).some(Boolean)) {
      setAvisoModal({ title: 'Missing!', text: 'Please select at least one item to backup.' })
      return
    }
    setAvisoModal(null)
    setOcupado(true)
    const r = await openDownload(token, 'settings/backup', parametrosBackup(seleccion), { ts: true })
    setOcupado(false)
    if (!r.ok) return
    setModal(null)
    setAviso({
      type: 'success',
      title: 'Backed Up!',
      text: 'Settings were backed up successfully.',
    })
  }

  async function hacerRestore(fichero: File | null, borrar: boolean) {
    // El orden de validación es el de upstream: primero el fichero, después
    // que haya al menos un elemento marcado (main.js:3137-3160).
    if (fichero == null) {
      setAvisoModal({ title: 'Missing!', text: 'Please select a backup zip file to restore.' })
      return
    }
    if (!Object.values(seleccion).some(Boolean)) {
      setAvisoModal({ title: 'Missing!', text: 'Please select at least one item to restore.' })
      return
    }
    setAvisoModal(null)
    setOcupado(true)
    const outcome = await restoreSettings(token, fichero, seleccion, borrar)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAvisoModal({
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    aplicar(outcome.data.response)
    setModal(null)
    setAviso({
      type: 'success',
      title: 'Restored!',
      text: 'Settings were restored successfully.',
    })
  }

  const props = { f: form, set, en }

  return (
    <div className={styles.wrap}>
      {/* El título es la sub-pestaña, no «Settings»: las nueve decían lo mismo,
          así que no servía ni para orientarse ni para buscar con Ctrl+F. */}
      <SectionHeader seccion="Settings" titulo={activa} />

      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

      <div>
        {activa === 'General' && <General {...props} />}
        {activa === 'Web Service' && <WebService {...props} />}
        {activa === 'Optional Protocols' && <OptionalProtocols {...props} />}
        {activa === 'TSIG' && <Tsig {...props} />}
        {activa === 'Recursion' && <Recursion {...props} />}
        {activa === 'Cache' && <Cache {...props} />}
        {activa === 'Blocking' && (
          <Blocking
            {...props}
            extra={{
              temporaryDisableBlockingTill: ajustes.temporaryDisableBlockingTill,
              blockListNextUpdatedOn: proximaLista,
              onTemporaryDisable: pedirDesactivarBloqueo,
              onUpdateNow: () => setConfirmar('update'),
              ocupado,
            }}
          />
        )}
        {activa === 'Proxy & Forwarders' && <ProxyForwarders {...props} />}
        {activa === 'Logging' && <Logging {...props} />}
      </div>

      <div className={styles.bar}>
        {canModify && (
          <Button variant="primary" disabled={ocupado} onClick={() => void guardar()}>
            Save Settings
          </Button>
        )}
        {canFlushCache && (
          <Button variant="danger" disabled={ocupado} onClick={() => setConfirmar('flush')}>
            Flush Cache
          </Button>
        )}
        <div className={styles.spacer} />
        {canBackup && (
          <>
            <Button
              onClick={() => {
                setSeleccion(seleccionInicialBackup())
                setAvisoModal(null)
                setModal('backup')
              }}
            >
              Backup Settings
            </Button>
            <Button
              onClick={() => {
                setSeleccion(seleccionInicialBackup())
                setAvisoModal(null)
                setModal('restore')
              }}
            >
              Restore Settings
            </Button>
          </>
        )}
      </div>

      <Confirm
        open={confirmar === 'flush'}
        onOpenChange={(o) => setConfirmar(o ? 'flush' : null)}
        title="Flush Cache"
        texto="Are you sure to flush the DNS Server cache?"
        ocupado={ocupado}
        onConfirm={() => void vaciarCache()}
      />
      <Confirm
        open={confirmar === 'disable'}
        onOpenChange={(o) => setConfirmar(o ? 'disable' : null)}
        title="Temporary Disable Blocking"
        texto={`Are you sure to temporarily disable blocking for ${form.temporaryDisableBlockingMinutes} minute(s)?`}
        ocupado={ocupado}
        onConfirm={() => void desactivarBloqueo()}
      />
      <Confirm
        open={confirmar === 'update'}
        onOpenChange={(o) => setConfirmar(o ? 'update' : null)}
        title="Update Block Lists"
        texto="Are you sure to force download and update the block lists?"
        ocupado={ocupado}
        onConfirm={() => void actualizarListas()}
      />

      <BackupDialog
        open={modal === 'backup'}
        onOpenChange={(o) => setModal(o ? 'backup' : null)}
        seleccion={seleccion}
        onSeleccion={setSeleccion}
        aviso={avisoModal}
        ocupado={ocupado}
        onBackup={() => void hacerBackup()}
      />
      <RestoreDialog
        open={modal === 'restore'}
        onOpenChange={(o) => setModal(o ? 'restore' : null)}
        seleccion={seleccion}
        onSeleccion={setSeleccion}
        aviso={avisoModal}
        ocupado={ocupado}
        onRestore={(fichero, borrar) => void hacerRestore(fichero, borrar)}
      />
    </div>
  )
}
