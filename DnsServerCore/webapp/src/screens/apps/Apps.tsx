import { useCallback, useEffect, useState } from 'react'
import {
  downloadAndUpdate,
  getAppConfig,
  listApps,
  uninstallApp,
  type InstalledApp,
} from '../../api/apps'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { AppConfig } from './AppConfig'
import { AppCard } from './AppCard'
import { InstallApp } from './InstallApp'
import { StoreApps } from './StoreApps'
import { UpdateApp } from './UpdateApp'
import { Empty, Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import styles from './Apps.module.css'

/*
Réplica de la pestaña Apps (apps.js + index.html:807-835).

Dos cosas de upstream que se conservan aunque el dibujo del rediseño enseñe sólo
tres botones por tarjeta:

  1. «Update» y «Store Update» son acciones DISTINTAS (apps.js:130-131). La
     primera sube un zip propio; la segunda descarga la versión de la tienda.
     Fundirlas quitaría funcionalidad, así que «Store Update» sigue ahí y sólo
     aparece cuando el servidor dice `updateAvailable`.
  2. El desplegable «More Details» con las clases del app, sus etiquetas y la
     `recordDataTemplate` (apps.js:74-113). Esa plantilla es lo que se copia
     para escribir un registro APP; sin ella la pantalla pierde utilidad real.

Lo que NO está: el badge Enabled/Disabled ni el botón «Enable» del dibujo. La
API no tiene ese concepto —ni `apps/list` ni `WriteAppAsJson` traen nada
parecido— y un app instalado está siempre activo. Inventarlo sería añadir
funcionalidad.
*/
export interface AlertState { type: AlertType; title: string; text: string }

type Modal =
  | { kind: 'store' }
  | { kind: 'install' }
  | { kind: 'update'; name: string }
  | { kind: 'config'; name: string; config: string }

export function error(outcome: { kind: string; message?: string }): AlertState {
  return {
    type: 'danger',
    title: 'Error!',
    text: outcome.kind === 'error' ? (outcome.message ?? '') : 'Invalid token or session expired.',
  }
}

export function Apps({ token }: { token: string | null }) {
  const [apps, setApps] = useState<InstalledApp[] | null>(null)
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [modal, setModal] = useState<Modal | null>(null)
  const [ocupado, setOcupado] = useState<string | null>(null)

  const recargar = useCallback(async () => {
    const outcome = await listApps(token)
    if (outcome.kind === 'ok') {
      setApps(outcome.data.response.apps)
      return
    }
    setApps([])
    setAlert(error(outcome))
  }, [token])

  useEffect(() => {
    void recargar()
  }, [recargar])

  // apps.js:425-449 — la confirmación y el aviso son literales de upstream.
  async function desinstalar(name: string) {
    if (!window.confirm(`Are you sure you want to uninstall the DNS application '${name}'?`)) return

    setOcupado(name)
    const outcome = await uninstallApp(token, name)
    setOcupado(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setAlert({
      type: 'success',
      title: 'App Uninstalled!',
      text: `DNS application '${name}' was uninstalled successfully.`,
    })
    await recargar()
  }

  // apps.js:253-290, con `isModal` a false: el aviso sale en la página.
  async function actualizarDesdeTienda(app: InstalledApp) {
    if (!app.updateUrl) return

    setOcupado(app.name)
    const outcome = await downloadAndUpdate(token, app.name, app.updateUrl)
    setOcupado(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setAlert({
      type: 'success',
      title: 'Store App Updated!',
      text: `DNS application '${app.name}' was updated successfully from DNS App Store.`,
    })
    await recargar()
  }

  // apps.js:459-491 — la config se lee ANTES de abrir el modal, y del nodo
  // primario del clúster. `config` puede venir nula; el editor queda vacío.
  async function abrirConfig(name: string) {
    setOcupado(name)
    const outcome = await getAppConfig(token, name)
    setOcupado(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setModal({ kind: 'config', name, config: outcome.data.response.config ?? '' })
  }

  // El recuento de apps instaladas ya no va en la cabecera: la píldora de
  // cabecera es para ESTADO, y un recuento con ese mismo aspecto era una de las
  // incongruencias. Aquí sólo queda lo que sí es estado: hay actualizaciones.
  const conUpdate = (apps ?? []).filter((a) => a.updateAvailable).length

  return (
    <>
      {alert && (
        <div style={{ marginBottom: 14 }}>
          <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
            {alert.text}
          </Alert>
        </div>
      )}

      <SectionHeader
        titulo="Apps"
        etiquetas={
          conUpdate > 0 ? (
            <Tag tone="warn">
              {conUpdate === 1 ? '1 update available' : `${conUpdate} updates available`}
            </Tag>
          ) : undefined
        }
        acciones={
          <>
            <Button variant="primary" onClick={() => setModal({ kind: 'store' })}>
              App Store
            </Button>
            <Button onClick={() => setModal({ kind: 'install' })}>Install from file</Button>
          </>
        }
      />

      {apps === null ? (
        <Loading />
      ) : apps.length === 0 ? (
        <Empty
          titulo="No apps installed"
          acciones={
            <Button variant="primary" onClick={() => setModal({ kind: 'store' })}>
              Open App Store
            </Button>
          }
        >
          DNS Apps add behaviour to the server — query logging, advanced blocking, split horizon —
          without touching the base configuration. Open the store to see what is available.
        </Empty>
      ) : (
        <ul className={styles.apps}>
          {apps.map((app) => (
            <AppCard
              key={app.name}
              app={app}
              ocupado={ocupado === app.name}
              onConfig={() => void abrirConfig(app.name)}
              onUpdate={() => setModal({ kind: 'update', name: app.name })}
              onStoreUpdate={() => void actualizarDesdeTienda(app)}
              onUninstall={() => void desinstalar(app.name)}
            />
          ))}
        </ul>
      )}

      <StoreApps
        open={modal?.kind === 'store'}
        onOpenChange={(o) => setModal(o ? { kind: 'store' } : null)}
        token={token}
        onChanged={() => void recargar()}
      />
      <InstallApp
        open={modal?.kind === 'install'}
        onOpenChange={(o) => setModal(o ? { kind: 'install' } : null)}
        token={token}
        onInstalled={(name) => {
          setModal(null)
          setAlert({
            type: 'success',
            title: 'App Installed!',
            text: `DNS application '${name}' was installed successfully.`,
          })
          void recargar()
        }}
      />
      <UpdateApp
        open={modal?.kind === 'update'}
        onOpenChange={(o) => setModal(o && modal?.kind === 'update' ? modal : null)}
        token={token}
        name={modal?.kind === 'update' ? modal.name : ''}
        onUpdated={(name) => {
          setModal(null)
          setAlert({
            type: 'success',
            title: 'App Updated!',
            text: `DNS application '${name}' was updated successfully.`,
          })
          void recargar()
        }}
      />
      <AppConfig
        open={modal?.kind === 'config'}
        onOpenChange={(o) => setModal(o && modal?.kind === 'config' ? modal : null)}
        token={token}
        name={modal?.kind === 'config' ? modal.name : ''}
        initialConfig={modal?.kind === 'config' ? modal.config : ''}
        onSaved={(name) => {
          setModal(null)
          setAlert({
            type: 'success',
            title: 'App Config Saved!',
            text: `The DNS application '${name}' config was saved and reloaded successfully.`,
          })
        }}
      />
    </>
  )
}
