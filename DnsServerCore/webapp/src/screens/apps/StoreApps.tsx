import { useCallback, useEffect, useState } from 'react'
import { downloadAndInstall, downloadAndUpdate, listStoreApps, uninstallApp, type StoreApp } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { error, type AlertState } from './Apps'
import { Empty, Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import styles from './Apps.module.css'
import { Avisador } from '../../ui/Avisador'
import { Confirmar } from '../../ui/Confirmar'

/*
A replica of `modalStoreApps` (index.html:6148-6183) and of the three actions
that come out of it: `installStoreApp`, `updateStoreApp` with `isModal` true and
`uninstallStoreApp` (apps.js:137-328).

The alerts of these three go INSIDE the modal, not on the page: upstream passes
them `divStoreAppsAlert` as a placeholder. The tab's ones (install by zip,
uninstall from the card, save config) go on the page. The difference is kept.

Upstream, after an action, patches the row by hand: hides "Install", shows
"Uninstall"… Here the list is asked for again. The visible result is the same and
it avoids upstream's lag, where `installedApp` comes without the update fields
and the freshly placed row is left without its "Store Update" button.
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
  const [porDesinstalar, setPorDesinstalar] = useState<StoreApp | null>(null)

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

  /*
  apps.js:292-294 — the same literal confirmation as the tab's.

  It stacks over this dialog, which is what Radix does with a modal inside
  another. Before it was the browser's native `confirm()`, the only step of this
  console that still opened the operating system's dialog.
  */
  function desinstalar(app: StoreApp) {
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
      tamano="medio"
      title="DNS App Store"
    >
      <Avisador aviso={alert} onCerrar={() => setAlert(null)} />

      <Confirmar
        abierto={porDesinstalar !== null}
        titulo="Uninstall App"
        texto={`Are you sure you want to uninstall the DNS application '${porDesinstalar?.name ?? ''}'?`}
        etiqueta="Uninstall"
        onCerrar={() => setPorDesinstalar(null)}
        onConfirmar={() => porDesinstalar && desinstalar(porDesinstalar)}
      />

      {storeApps === null ? (
        <Loading />
      ) : storeApps.length === 0 ? (
        <Empty>No Apps Found</Empty>
      ) : (
        <>
          <ul className={styles.store}>
            {storeApps.map((app) => {
              const hayUpdate = app.installed && app.updateAvailable === true
              // apps.js:164 — installed shows ITS version; not installed, the store's.
              const version = app.installed ? (app.installedVersion ?? app.version) : app.version
              return (
                <li key={app.name} className={styles.srow} aria-label={app.name}>
                  <div>
                    <div className={styles.sname}>{app.name}</div>
                    <div className={styles.slabels}>
                      <Tag>Version {version}</Tag>
                      {hayUpdate && (
                        <Tag tone="warn">
                          Update {app.version}
                        </Tag>
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
                        onClick={() => setPorDesinstalar(app)}
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
