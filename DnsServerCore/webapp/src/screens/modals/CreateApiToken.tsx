import { useState } from 'react'
import { apiRequest } from '../../api/client'
import { type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { noticeFromFailure } from '../../lib/aviso'
import { Notifier } from '../../ui/Avisador'

/* A replica of `createMyApiToken()` (auth.js:337-381). */
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
    setAlert(noticeFromFailure(outcome))
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="medium"
      title="Create API Token"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void create()}>
            Create
          </Button>
        </>
      }
    >
      <Notifier notice={alert} onClose={() => setAlert(null)} />
      <LabeledInput label="Username" value={username} readOnly />
      <LabeledInput label="Token Name" placeholder="token name" value={name} onChange={(e) => setName(e.target.value)} />
      {created && <LabeledInput label="Token" mono value={created} readOnly />}
    </Dialog>
  )
}
