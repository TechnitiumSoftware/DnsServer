import { useEffect, useState } from 'react'
import { setAppConfig } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Field } from '../../ui/Field'
import { error, type AlertState } from './Apps'
import styles from './Apps.module.css'
import { Avisador } from '../../ui/Avisador'

/*
A replica of `modalAppConfig` (index.html:6255-6280) and `saveAppConfig`
(apps.js:493-522).

It is a TEXT EDITOR, not a form: the content of `dnsApp.config` is defined by each
app and the console does not know what fields it has. Upstream puts a 15-row
`<textarea>` with the spellchecker off, and that is what is here.

The config arrives already read from the screen, because upstream also asks for it
BEFORE opening the modal (the "Config" button sits at "Loading...").
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
