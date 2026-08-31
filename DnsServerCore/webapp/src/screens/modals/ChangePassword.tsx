import { useState } from 'react'
import { apiRequest } from '../../api/client'
import { type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { noticeFromFailure } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

/*
A replica of `changePassword()` (auth.js:426-497).

The ORDER of the validations is contract, just like the texts: upstream checks
the current password first, then the new one, then the confirmation, then that
they match, and only then the OTP —and the OTP only if the user has 2FA on.
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
    setAlert(noticeFromFailure(outcome))
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Change Password"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={alert} onClose={() => setAlert(null)} />
      <LabeledInput
        label="Current Password"
        placeholder="current password"
        type="password"
        value={current}
        onChange={(e) => setCurrent(e.target.value)}
      />
      <LabeledInput
        label="New Password"
        placeholder="new password"
        type="password"
        value={next}
        onChange={(e) => setNext(e.target.value)}
      />
      <LabeledInput
        label="Confirm Password"
        placeholder="confirm password"
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
