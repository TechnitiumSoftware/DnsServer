import { useEffect, useRef, useState } from 'react'
import { installApp } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { error, type AlertState } from './Apps'
import { Avisador } from '../../ui/Avisador'

/*
Réplica de `showInstallAppModal` / `installApp` (apps.js:198-209 y 330-379).

El orden de validación es el de upstream y no se toca: PRIMERO el nombre,
DESPUÉS el fichero. Los dos avisos son literales.
*/
export function InstallApp({
  open,
  onOpenChange,
  token,
  onInstalled,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  onInstalled: (name: string) => void
}) {
  const [name, setName] = useState('')
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setName('')
      setAlert(null)
      setBusy(false)
    }
  }, [open])

  async function instalar() {
    if (name === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter an application name.' })
      return
    }

    const file = fileRef.current?.files?.[0]
    if (!file) {
      setAlert({
        type: 'warning',
        title: 'Missing!',
        text: 'Please select an application zip file to install.',
      })
      return
    }

    setBusy(true)
    const outcome = await installApp(token, name, file)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAlert(error(outcome))
      return
    }
    onInstalled(name)
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Install App"
      acciones={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void instalar()}>
            Install
          </Button>
        </>
      }
    >
      <Avisador aviso={alert} onCerrar={() => setAlert(null)} />
      <LabeledInput label="App Name" value={name} onChange={(e) => setName(e.target.value)} />
      <LabeledInput label="App Zip File" type="file" ref={fileRef} />
    </Dialog>
  )
}
