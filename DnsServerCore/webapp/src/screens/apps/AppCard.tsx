import { etiquetasDnsApp, type InstalledApp } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Chip } from '../../ui/Tag'
import styles from './Apps.module.css'

/*
Una tarjeta por app instalada. En upstream es una fila de tabla (apps.js:63-135);
el rediseño la convierte en tarjeta porque la descripción es larga. Lo que se
enseña es lo mismo, y en el mismo orden.

`updateAvailable` puede no venir: el servidor sólo escribe los tres campos de
actualización si el app está en el catálogo de la tienda. Por eso se comprueba
como opcional y no como booleano.
*/
export function AppCard({
  app,
  ocupado,
  onConfig,
  onUpdate,
  onStoreUpdate,
  onUninstall,
}: {
  app: InstalledApp
  ocupado: boolean
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
        <details className={styles.detalles}>
          <summary>More Details</summary>
          {app.dnsApps.map((d) => (
            <div key={d.classPath} className={styles.clase}>
              <div className={styles.clasePath}>{d.classPath}</div>
              <div className={styles.caps}>
                {etiquetasDnsApp(d).map((l) => (
                  <Chip key={l}>{l}</Chip>
                ))}
              </div>
              <p className={styles.claseDesc}>{d.description}</p>
              {/* apps.js:82 — la plantilla sólo se enseña para las clases que
                  atienden registros APP, que son las que la traen. */}
              {d.isAppRecordRequestHandler && d.recordDataTemplate != null && (
                <>
                  <div className={styles.plantillaK}>Record Data Template</div>
                  <pre className={styles.plantilla}>{d.recordDataTemplate}</pre>
                </>
              )}
            </div>
          ))}
        </details>
      )}

      <div className={styles.foot}>
        <Button disabled={ocupado} onClick={onConfig}>
          Config
        </Button>
        <Button disabled={ocupado} onClick={onUpdate}>
          Update
        </Button>
        {hayUpdate && (
          <Button variant="primary" disabled={ocupado} onClick={onStoreUpdate}>
            Store Update
          </Button>
        )}
        <Button variant="danger" disabled={ocupado} onClick={onUninstall}>
          Uninstall
        </Button>
      </div>
    </li>
  )
}
