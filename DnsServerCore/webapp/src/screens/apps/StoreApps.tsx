import { useCallback, useEffect, useState } from 'react'
import { downloadAndInstall, downloadAndUpdate, listStoreApps, uninstallApp, type StoreApp } from '../../api/apps'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { error, type AlertState } from './Apps'
import styles from './Apps.module.css'

/*
Réplica de `modalStoreApps` (index.html:6148-6183) y de las tres acciones que
salen de él: `installStoreApp`, `updateStoreApp` con `isModal` a true y
`uninstallStoreApp` (apps.js:137-328).

Los avisos de estas tres van DENTRO del modal, no en la página: upstream les
pasa `divStoreAppsAlert` como placeholder. Los de la pestaña (instalar por zip,
desinstalar desde la tarjeta, guardar config) van en la página. La diferencia se
conserva.

Upstream, tras una acción, retoca la fila a mano: esconde «Install», enseña
«Uninstall»... Aquí se vuelve a pedir la lista. El resultado visible es el mismo
y evita el desfase de upstream, donde `installedApp` viene sin los campos de
actualización y la fila recién puesta se queda sin su botón «Store Update».
*/
export function StoreApps({
  open,
  onOpenChange,
  token,
  onChanged,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  onChanged: () => void
}) {
  const [storeApps, setStoreApps] = useState<StoreApp[] | null>(null)
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [ocupado, setOcupado] = useState<string | null>(null)

  const cargar = useCallback(async () => {
    const outcome = await listStoreApps(token)
    if (outcome.kind === 'ok') {
      setStoreApps(outcome.data.response.storeApps)
      return
    }
    setStoreApps([])
    setAlert(error(outcome))
  }, [token])

  useEffect(() => {
    if (!open) return
    setAlert(null)
    setStoreApps(null)
    void cargar()
  }, [open, cargar])

  async function tras(app: StoreApp, ok: AlertState, llamada: Promise<{ kind: string; message?: string }>) {
    setOcupado(app.name)
    const outcome = await llamada
    setOcupado(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setAlert(ok)
    onChanged()
    await cargar()
  }

  function instalar(app: StoreApp) {
    return tras(
      app,
      {
        type: 'success',
        title: 'Store App Installed!',
        text: `DNS application '${app.name}' was installed successfully from DNS App Store.`,
      },
      downloadAndInstall(token, app.name, app.url),
    )
  }

  function actualizar(app: StoreApp) {
    return tras(
      app,
      {
        type: 'success',
        title: 'Store App Updated!',
        text: `DNS application '${app.name}' was updated successfully from DNS App Store.`,
      },
      downloadAndUpdate(token, app.name, app.url),
    )
  }

  // apps.js:292-294 — misma confirmación literal que la de la pestaña.
  function desinstalar(app: StoreApp) {
    if (!window.confirm(`Are you sure you want to uninstall the DNS application '${app.name}'?`)) {
      return Promise.resolve()
    }
    return tras(
      app,
      {
        type: 'success',
        title: 'Store App Uninstalled!',
        text: `DNS application '${app.name}' was uninstalled successfully.`,
      },
      uninstallApp(token, app.name),
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="DNS App Store"
      footer={<Button onClick={() => onOpenChange(false)}>Close</Button>}
    >
      {alert && (
        <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
          {alert.text}
        </Alert>
      )}

      {storeApps === null ? (
        <div className={styles.cargando}>Loading…</div>
      ) : storeApps.length === 0 ? (
        <div className={styles.vacioStore}>No Apps Found</div>
      ) : (
        <>
          <ul className={styles.store}>
            {storeApps.map((app) => {
              const hayUpdate = app.installed && app.updateAvailable === true
              // apps.js:164 — instalada enseña SU versión; sin instalar, la de la tienda.
              const version = app.installed ? (app.installedVersion ?? app.version) : app.version
              return (
                <li key={app.name} className={styles.srow} aria-label={app.name}>
                  <div>
                    <div className={styles.sname}>{app.name}</div>
                    <div className={styles.slabels}>
                      <span className={styles.tag}>Version {version}</span>
                      {hayUpdate && (
                        <span className={`${styles.tag} ${styles.tagUpd}`}>
                          Update {app.version}
                        </span>
                      )}
                    </div>
                    <p className={styles.sdesc}>{app.description}</p>
                    <div className={styles.smeta}>
                      <div>
                        <b>App Zip File</b>: {app.url}
                      </div>
                      <div>
                        <b>Size</b>: {app.size}
                      </div>
                    </div>
                  </div>
                  <div className={styles.sacts}>
                    {!app.installed && (
                      <Button
                        variant="primary"
                        disabled={ocupado === app.name}
                        onClick={() => void instalar(app)}
                      >
                        Install
                      </Button>
                    )}
                    {hayUpdate && (
                      <Button disabled={ocupado === app.name} onClick={() => void actualizar(app)}>
                        Update
                      </Button>
                    )}
                    {app.installed && (
                      <Button
                        variant="danger"
                        disabled={ocupado === app.name}
                        onClick={() => void desinstalar(app)}
                      >
                        Uninstall
                      </Button>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
          <div className={styles.total}>Total Apps: {storeApps.length}</div>
        </>
      )}
    </Dialog>
  )
}
