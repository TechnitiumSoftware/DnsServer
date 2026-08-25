import { useEffect, useRef, useState } from 'react'
import { updateApp } from '../../api/apps'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { error, type AlertState } from './Apps'

/*
Réplica de `showUpdateAppModal` / `updateApp` (apps.js:211-218 y 381-423).

El nombre viene puesto y DESHABILITADO (index.html:6232): actualizar es
reemplazar el zip de un app que ya existe, no renombrarlo. Aquí sólo se valida
el fichero, igual que en upstream.
*/
export function UpdateApp({
  open,
  onOpenChange,
  token,
  name,
  onUpdated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  name: string
  onUpdated: (name: string) => void
}) {
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setAlert(null)
      setBusy(false)
    }
  }, [open])

  async function actualizar() {
    const file = fileRef.current?.files?.[0]
    if (!file) {
      setAlert({
        type: 'warning',
        title: 'Missing!',
        text: 'Please select an application zip file to update.',
      })
      return
    }

    setBusy(true)
    const outcome = await updateApp(token, name, file)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    onUpdated(name)
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Update App"
      footer={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void actualizar()}>
            Update
          </Button>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </>
      }
    >
      {alert && (
        <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
          {alert.text}
        </Alert>
      )}
      <LabeledInput label="App Name" value={name} disabled readOnly />
      <LabeledInput label="App Zip File" type="file" ref={fileRef} />
    </Dialog>
  )
}
