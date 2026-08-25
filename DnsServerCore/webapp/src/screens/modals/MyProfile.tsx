import { useEffect, useState } from 'react'
import { apiRequest } from '../../api/client'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'

/*
Réplica de `showMyProfileModal` / `saveMyProfile` (auth.js:642-794).

Dos detalles del contrato: el nombre visible se DESHABILITA para usuarios de
SSO, y por eso `displayName` sólo se manda si el campo no está deshabilitado
(auth.js:756-761). El tipo de usuario se muestra como «Remote/SSO» o «Local».
*/
interface Profile {
  displayName: string
  username: string
  isSsoUser: boolean
  sessionTimeoutSeconds: number
}

export function MyProfile({
  open,
  onOpenChange,
  token,
  onSaved,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  onSaved?: (displayName: string) => void
}) {
  const [profile, setProfile] = useState<Profile | null>(null)
  const [displayName, setDisplayName] = useState('')
  const [timeout, setTimeoutSeconds] = useState('')
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setAlert(null)
    void (async () => {
      const outcome = await apiRequest<{ response: Profile }>('user/profile/get', { token })
      if (outcome.kind === 'ok') {
        setProfile(outcome.data.response)
        setDisplayName(outcome.data.response.displayName)
        setTimeoutSeconds(String(outcome.data.response.sessionTimeoutSeconds))
      }
    })()
  }, [open, token])

  async function save() {
    if (!profile) return
    const body: Record<string, string> = { sessionTimeoutSeconds: timeout }
    if (!profile.isSsoUser) body.displayName = displayName

    setBusy(true)
    const outcome = await apiRequest('user/profile/set', { token, body })
    setBusy(false)

    if (outcome.kind === 'ok') {
      setAlert({
        type: 'success',
        title: 'Profile Saved!',
        text: 'User profile was saved successfully.',
      })
      onSaved?.(displayName)
      return
    }
    setAlert({
      type: 'danger',
      title: 'Error!',
      text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
    })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="My Profile"
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      {alert && (
        <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
          {alert.text}
        </Alert>
      )}
      <LabeledInput label="Username" value={profile?.username ?? ''} readOnly />
      <LabeledInput label="User Type" value={profile?.isSsoUser ? 'Remote/SSO' : 'Local'} readOnly />
      <LabeledInput
        label="Display Name"
        value={displayName}
        disabled={profile?.isSsoUser ?? false}
        onChange={(e) => setDisplayName(e.target.value)}
      />
      <LabeledInput
        label="Session Timeout"
        mono
        value={timeout}
        onChange={(e) => setTimeoutSeconds(e.target.value)}
      />
    </Dialog>
  )
}
