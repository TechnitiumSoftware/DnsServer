import { useState } from 'react'
import { apiRequest } from '../../api/client'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { avisoDeFallo } from '../../lib/aviso'

/* Réplica de `createMyApiToken()` (auth.js:337-381). */
export function CreateApiToken({
  open,
  onOpenChange,
  username,
  token,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  username: string
  token: string | null
}) {
  const [name, setName] = useState('')
  const [created, setCreated] = useState<string | null>(null)
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  async function create() {
    if (name === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter a token name.' })
      return
    }
    setBusy(true)
    const outcome = await apiRequest<{ token: string }>('user/createToken', {
      method: 'POST',
      token,
      body: { tokenName: name },
    })
    setBusy(false)

    if (outcome.kind === 'ok') {
      setCreated((outcome.data as { token?: string }).token ?? null)
      setAlert({
        type: 'success',
        title: 'Token Created!',
        text: 'API token was created successfully.',
      })
      return
    }
    setAlert(avisoDeFallo(outcome))
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      tamano="medio"
      title="Create API Token"
      acciones={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void create()}>
            Create
          </Button>
        </>
      }
    >
      {alert && (
        <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
          {alert.text}
        </Alert>
      )}
      <LabeledInput label="Username" value={username} readOnly />
      <LabeledInput label="Token Name" value={name} onChange={(e) => setName(e.target.value)} />
      {created && <LabeledInput label="Token" mono value={created} readOnly />}
    </Dialog>
  )
}
