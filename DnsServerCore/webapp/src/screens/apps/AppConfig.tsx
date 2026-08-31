import { useEffect, useState } from 'react'
import { setAppConfig } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Field } from '../../ui/Field'
import { error, type AlertState } from './Apps'
import styles from './Apps.module.css'
import { Avisador } from '../../ui/Avisador'

/*
Réplica de `modalAppConfig` (index.html:6255-6280) y `saveAppConfig`
(apps.js:493-522).

Es un EDITOR DE TEXTO, no un formulario: el contenido de `dnsApp.config` lo
define cada app y la consola no sabe qué campos tiene. Upstream pone un
`<textarea>` de 15 filas con el corrector ortográfico apagado, y eso es lo que
hay aquí.

La config llega ya leída desde la pantalla, porque upstream también la pide
ANTES de abrir el modal (el botón «Config» se queda en «Loading...»).
*/
export function AppConfig({
  open,
  onOpenChange,
  token,
  name,
  initialConfig,
  onSaved,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  name: string
  initialConfig: string
  onSaved: (name: string) => void
}) {
  const [config, setConfig] = useState(initialConfig)
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (open) {
      setConfig(initialConfig)
      setAlert(null)
      setBusy(false)
    }
  }, [open, initialConfig])

  async function guardar() {
    setBusy(true)
    const outcome = await setAppConfig(token, name, config)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    onSaved(name)
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      tamano="medio"
      title={`App Config - ${name}`}
      acciones={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={alert} onCerrar={() => setAlert(null)} />
      <p className={styles.nota}>
        Edit the <code>dnsApp.config</code> config file below as required by the DNS application.
      </p>
      <Field label="Config File">
        {(id) => (
          <textarea
            id={id}
            className={styles.config}
            spellCheck={false}
            value={config}
            onChange={(e) => setConfig(e.target.value)}
          />
        )}
      </Field>
      <p className={styles.nota}>
        Note: The app will reload the config automatically after you save it.
      </p>
    </Dialog>
  )
}
