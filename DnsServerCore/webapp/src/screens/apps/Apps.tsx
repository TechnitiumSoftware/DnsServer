import { useCallback, useEffect, useState } from 'react'
import {
  downloadAndUpdate,
  getAppConfig,
  listApps,
  uninstallApp,
  type InstalledApp,
} from '../../api/apps'
import { type AlertType } from '../../ui/Alert'
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
import { noticeFromFailure } from '../../lib/aviso'
import { Notifier } from '../../ui/Avisador'
import { Confirm } from '../../ui/Confirmar'

/*
A replica of the Apps tab (apps.js + index.html:807-835).

Two things from upstream that are kept even though the redesign mockup shows only
three buttons per card:

  1. "Update" and "Store Update" are DIFFERENT actions (apps.js:130-131). The
     first uploads your own zip; the second downloads the store's version.
     Merging them would remove functionality, so "Store Update" stays and only
     appears when the server says `updateAvailable`.
  2. The "More Details" disclosure with the app's classes, their labels and the
     `recordDataTemplate` (apps.js:74-113). That template is what gets copied to
     write an APP record; without it the screen loses real usefulness.

What is NOT here: the Enabled/Disabled badge nor the mockup's "Enable" button.
The API has no such concept —neither `apps/list` nor `WriteAppAsJson` bring
anything like it— and an installed app is always active. Inventing it would be
adding functionality.
*/
export interface AlertState { type: AlertType; title: string; text: string }

type Modal =
  | { kind: 'store' }
  | { kind: 'install' }
  | { kind: 'update'; name: string }
  | { kind: 'config'; name: string; config: string }

export function error(outcome: { kind: string; message?: string }): AlertState {
  return noticeFromFailure(outcome)
}

export function Apps({ token }: { token: string | null }) {
  const [apps, setApps] = useState<InstalledApp[] | null>(null)
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [modal, setModal] = useState<Modal | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [pendingUninstall, setPorDesinstalar] = useState<string | null>(null)

  const reload = useCallback(async () => {
    const outcome = await listApps(token)
    if (outcome.kind === 'ok') {
      setApps(outcome.data.response.apps)
      return
    }
    setApps([])
    setAlert(error(outcome))
  }, [token])

  useEffect(() => {
    void reload()
  }, [reload])

  /*
  apps.js:425-449 — the confirmation and the alert are upstream literals.

  The confirmation step is `ui/Confirmar`, as in the console's other eleven
  destructive actions. Here the browser's native `confirm()` had been left
  behind: the same operating-system dialog the redesign replaced everywhere, on
  an action that uninstalls an application from the server.
  */
  async function uninstall(name: string) {
    setBusy(name)
    const outcome = await uninstallApp(token, name)
    setBusy(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setAlert({
      type: 'success',
      title: 'App Uninstalled!',
      text: `DNS application '${name}' was uninstalled successfully.`,
    })
    await reload()
  }

  // apps.js:253-290, with `isModal` false: the alert comes out on the page.
  async function actualizarDesdeTienda(app: InstalledApp) {
    if (!app.updateUrl) return

    setBusy(app.name)
    const outcome = await downloadAndUpdate(token, app.name, app.updateUrl)
    setBusy(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setAlert({
      type: 'success',
      title: 'Store App Updated!',
      text: `DNS application '${app.name}' was updated successfully from DNS App Store.`,
    })
    await reload()
  }

  // apps.js:459-491 — the config is read BEFORE opening the modal, and from the
  // cluster's primary node. `config` can come null; the editor is left empty.
  async function openConfig(name: string) {
    setBusy(name)
    const outcome = await getAppConfig(token, name)
    setBusy(null)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    setModal({ kind: 'config', name, config: outcome.data.response.config ?? '' })
  }

  // The installed-apps count no longer goes in the header: the header pill
  // is for STATE, and a count that looked exactly like it was one of the
  // inconsistencies. What is left here is what really is state: there are updates.
  const withUpdate = (apps ?? []).filter((a) => a.updateAvailable).length

  return (
    <>
      <Notifier notice={alert} onClose={() => setAlert(null)} />

      <SectionHeader
        title="Apps"
        labels={
          withUpdate > 0 ? (
            <Tag tone="warn">
              {withUpdate === 1 ? '1 update available' : `${withUpdate} updates available`}
            </Tag>
          ) : undefined
        }
        actions={
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
          title="No apps installed"
          actions={
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
              busy={busy === app.name}
              onConfig={() => void openConfig(app.name)}
              onUpdate={() => setModal({ kind: 'update', name: app.name })}
              onStoreUpdate={() => void actualizarDesdeTienda(app)}
              onUninstall={() => setPorDesinstalar(app.name)}
            />
          ))}
        </ul>
      )}

      <Confirm
        open={pendingUninstall !== null}
        title="Uninstall App"
        text={`Are you sure you want to uninstall the DNS application '${pendingUninstall ?? ''}'?`}
        label="Uninstall"
        onClose={() => setPorDesinstalar(null)}
        onConfirm={() => pendingUninstall && uninstall(pendingUninstall)}
      />

      <StoreApps
        open={modal?.kind === 'store'}
        onOpenChange={(o) => setModal(o ? { kind: 'store' } : null)}
        token={token}
        onChanged={() => void reload()}
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
          void reload()
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
          void reload()
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
