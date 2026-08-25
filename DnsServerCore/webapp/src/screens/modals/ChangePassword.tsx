import { useState } from 'react'
import { apiRequest } from '../../api/client'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'

/*
Réplica de `changePassword()` (auth.js:426-497).

El ORDEN de las validaciones es contrato, igual que los textos: upstream
comprueba primero la contraseña actual, luego la nueva, luego la confirmación,
luego que coincidan, y sólo entonces el OTP —y el OTP sólo si el usuario tiene
2FA activo.
*/
export function ChangePassword({
  open,
  onOpenChange,
  totpEnabled,
  token,
  onChanged,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  totpEnabled: boolean
  token: string | null
  onChanged?: () => void
}) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [totp, setTotp] = useState('')
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  function warn(text: string, title = 'Missing!') {
    setAlert({ type: 'warning', title, text })
  }

  async function save() {
    if (current === '') return warn('Please enter the current password.')
    if (next === '') return warn('Please enter new password.')
    if (confirm === '') return warn('Please enter confirm password.')
    if (next !== confirm) return warn('Passwords do not match. Please try again.', 'Mismatch!')
    if (totpEnabled && totp.length !== 6) {
      return warn('Please enter the 6-digit OTP that you see in your authenticator app.')
    }

    setBusy(true)
    const outcome = await apiRequest('user/changePassword', {
      method: 'POST',
      token,
      body: { pass: current, newPass: next, totp },
    })
    setBusy(false)

    if (outcome.kind === 'ok') {
      setAlert({
        type: 'success',
        title: 'Password Changed!',
        text: 'Password was changed successfully.',
      })
      onChanged?.()
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
      title="Change Password"
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
      <LabeledInput
        label="Current Password"
        type="password"
        value={current}
        onChange={(e) => setCurrent(e.target.value)}
      />
      <LabeledInput
        label="New Password"
        type="password"
        value={next}
        onChange={(e) => setNext(e.target.value)}
      />
      <LabeledInput
        label="Confirm Password"
        type="password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />
      {totpEnabled && (
        <LabeledInput
          label="OTP"
          mono
          inputMode="numeric"
          maxLength={6}
          value={totp}
          onChange={(e) => setTotp(e.target.value)}
        />
      )}
    </Dialog>
  )
}
