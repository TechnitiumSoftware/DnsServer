import { useCallback, useEffect, useState } from 'react'
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
import { BackupDialog, Confirmar, RestoreDialog } from './dialogs'
import { Fallo, Loading } from '../../ui/Empty'
import styles from './Settings.module.css'
import formulario from '../../ui/Ajustes.module.css'
import { avisoDeFallo, type Aviso } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'

/*
Settings. The console's biggest screen: in upstream, the General sub-tab alone is
5,452 px tall.

The sub-navigation is NOT mounted here. The nine sub-tabs live in the Shell's
side panel, nested under Settings, and arrive through the `sub` prop. This
component only decides which panel it draws and keeps A SINGLE form state for the
nine: upstream does not have nine forms either, it has one with nine tabs, and
"Save Settings" ALWAYS sends the fields of all nine wherever you are. Chopping it
up per tab would change what gets saved.

Two consequences of that to keep in mind:

  · A validation failure can be on another sub-tab. Upstream focuses the field
    even when its tab is hidden and the user sees nothing. Here the alert says
    what is missing and the screen jumps to the field's sub-tab.
  · The three permissions on the bar are different: saving requires
    `Settings.canModify`, flushing the cache `Cache.canDelete`, and backup and
    restore `Settings.canDelete` (main.js:906-930).
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


export interface SettingsProps {
  token: string | null
  /** The active sub-tab, the one the Shell's side panel marks. */
  sub?: string | null
  /** Lets the Shell follow the screen when a validation failure forces it to
   *  jump to another sub-tab. */
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
  const [aviso, setAviso] = useState<Aviso | null>(null)
  // The validation jump remembers which sub-tab it fired from: as soon as the
  // Shell asks for a different one, it stops holding. Deriving it this way avoids
  // an effect whose only job was to null it out, and the extra render it brings.
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
    return <Fallo>Unable to load the DNS Server settings.</Fallo>
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
      setAviso(avisoDeFallo(outcome))
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
    // main.js:2356 — the label becomes "Updating Now" without reloading the settings.
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
    // The validation order is upstream's: the file first, then that there is
    // at least one item checked (main.js:3137-3160).
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
      setAvisoModal(avisoDeFallo(outcome))
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
      {/* The title is the sub-tab, not "Settings": all nine said the same
          thing, so it was no use either for orienting yourself or for finding it
          with Ctrl+F. */}
      <SectionHeader seccion="Settings" titulo={activa} />

      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

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

      <div className={formulario.bar}>
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
        <div className={formulario.spacer} />
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

      <Confirmar
        abierto={confirmar === 'flush'}
        onCerrar={() => setConfirmar(null)}
        titulo="Flush Cache"
        etiqueta="Flush"
        variante="primary"
        texto="Are you sure to flush the DNS Server cache?"
        ocupado={ocupado}
        onConfirmar={() => void vaciarCache()}
      />
      <Confirmar
        abierto={confirmar === 'disable'}
        onCerrar={() => setConfirmar(null)}
        titulo="Temporary Disable Blocking"
        etiqueta="Disable"
        variante="primary"
        texto={`Are you sure to temporarily disable blocking for ${form.temporaryDisableBlockingMinutes} minute(s)?`}
        ocupado={ocupado}
        onConfirmar={() => void desactivarBloqueo()}
      />
      <Confirmar
        abierto={confirmar === 'update'}
        onCerrar={() => setConfirmar(null)}
        titulo="Update Block Lists"
        etiqueta="Update"
        variante="primary"
        texto="Are you sure to force download and update the block lists?"
        ocupado={ocupado}
        onConfirmar={() => void actualizarListas()}
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
