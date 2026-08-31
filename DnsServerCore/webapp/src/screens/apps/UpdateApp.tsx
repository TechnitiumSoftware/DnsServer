import { useEffect, useRef, useState } from 'react'
import { updateApp } from '../../api/apps'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { error, type AlertState } from './Apps'
import { Notifier } from '../../ui/Avisador'

/*
A replica of `showUpdateAppModal` / `updateApp` (apps.js:211-218 and 381-423).

The name comes filled in and DISABLED (index.html:6232): updating is replacing
the zip of an app that already exists, not renaming it. Only the file is
validated here, just as in upstream.
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
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void actualizar()}>
            Update
          </Button>
        </>
      }
    >
      <Notifier notice={alert} onClose={() => setAlert(null)} />
      <LabeledInput label="App Name" value={name} disabled readOnly />
      <LabeledInput label="App Zip File" type="file" ref={fileRef} />
    </Dialog>
  )
}
