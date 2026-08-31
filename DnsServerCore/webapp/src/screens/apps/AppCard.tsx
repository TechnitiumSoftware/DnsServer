import { etiquetasDnsApp, type InstalledApp } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Detalles } from '../../ui/Detalles'
import { Chip } from '../../ui/Tag'
import styles from './Apps.module.css'

/*
One card per installed app. In upstream it is a table row (apps.js:63-135); the
redesign turns it into a card because the description is long. What is shown is
the same, and in the same order.

`updateAvailable` may not come: the server only writes the three update fields if
the app is in the store's catalog. That is why it is checked as optional and not
as a boolean.
*/
export function AppCard({
  app,
  busy,
  onConfig,
  onUpdate,
  onStoreUpdate,
  onUninstall,
}: {
  app: InstalledApp
  busy: boolean
  onConfig: () => void
  onUpdate: () => void
  onStoreUpdate: () => void
  onUninstall: () => void
}) {
  const hayUpdate = app.updateAvailable === true && Boolean(app.updateUrl)

  return (
    <li className={styles.app} aria-label={app.name}>
      <div className={styles.ah}>
        <div>
          <h2>{app.name}</h2>
          <div className={styles.ver}>
            v{app.version} ·{' '}
            {hayUpdate ? (
              <span className={styles.nueva}>Update v{app.updateVersion}</span>
            ) : (
              'installed'
            )}
          </div>
        </div>
      </div>

      {app.description && <p className={styles.desc}>{app.description}</p>}

      {app.dnsApps.length > 0 && (
        <Detalles className={styles.detalles} summary="More Details">
          {app.dnsApps.map((d) => (
            <div key={d.classPath} className={styles.clase}>
              <div className={styles.clasePath}>{d.classPath}</div>
              <div className={styles.caps}>
                {etiquetasDnsApp(d).map((l) => (
                  <Chip key={l}>{l}</Chip>
                ))}
              </div>
              <p className={styles.claseDesc}>{d.description}</p>
              {/* apps.js:82 — the template is only shown for the classes that
                  serve APP records, which are the ones that bring it. */}
              {d.isAppRecordRequestHandler && d.recordDataTemplate != null && (
                <>
                  <div className={styles.plantillaK}>Record Data Template</div>
                  <pre className={styles.plantilla}>{d.recordDataTemplate}</pre>
                </>
              )}
            </div>
          ))}
        </Detalles>
      )}

      <div className={styles.foot}>
        <Button disabled={busy} onClick={onConfig}>
          Config
        </Button>
        <Button disabled={busy} onClick={onUpdate}>
          Update
        </Button>
        {hayUpdate && (
          <Button variant="primary" disabled={busy} onClick={onStoreUpdate}>
            Store Update
          </Button>
        )}
        <Button variant="danger" disabled={busy} onClick={onUninstall}>
          Uninstall
        </Button>
      </div>
    </li>
  )
}
