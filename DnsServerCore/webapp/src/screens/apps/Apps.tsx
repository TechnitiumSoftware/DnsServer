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
import { AppConfig } from './AppConfig'
import { AppCard } from './AppCard'
import { InstallApp } from './InstallApp'
import { StoreApps } from './StoreApps'
import { UpdateApp } from './UpdateApp'
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

  const conUpdate = (apps ?? []).filter((a) => a.updateAvailable).length
  const total = apps?.length ?? 0

  return (
    <>
      {alert && (
        <div style={{ marginBottom: 14 }}>
          <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
            {alert.text}
          </Alert>
        </div>
      )}

      <div className={styles.hrow}>
        <div>
          <h1>Apps</h1>
          {total > 0 && (
            <div className={styles.tags}>
              <span className={styles.tag}>
                {total} {total === 1 ? 'instalada' : 'instaladas'}
              </span>
              {conUpdate > 0 && (
                <span className={`${styles.tag} ${styles.tagUpd}`}>
                  {conUpdate} {conUpdate === 1 ? 'actualización' : 'actualizaciones'}
                </span>
              )}
            </div>
          )}
        </div>
        <div className={styles.acts}>
          <Button variant="primary" onClick={() => setModal({ kind: 'store' })}>
            App Store
          </Button>
          <Button onClick={() => setModal({ kind: 'install' })}>Install from file</Button>
        </div>
      </div>

      {apps === null ? (
        <div className={styles.cargando}>Cargando…</div>
      ) : apps.length === 0 ? (
        <div className={styles.empty}>
          <b>No hay apps instaladas</b>
          Las DNS Apps añaden comportamiento al servidor —registro de consultas, bloqueo avanzado,
          split horizon— sin tocar la configuración base. Abre la tienda para ver las disponibles.
          <div className={styles.emptyActs}>
            <Button variant="primary" onClick={() => setModal({ kind: 'store' })}>
              Abrir App Store
            </Button>
          </div>
        </div>
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
