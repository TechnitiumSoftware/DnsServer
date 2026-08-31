import { useEffect, useState } from 'react'
import { apiRequest } from '../../api/client'
import { type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { noticeFromFailure } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

/*
A replica of `showConfigure2FAModal` / `enable2FA` / `disable2FA`
(auth.js:498-641).

`user/2fa/init` returns `qrCodePngImage` (base64 PNG) and `secret`. The QR is
drawn as a `data:` URI, which the server's CSP DOES allow: it declares
`img-src 'self' data:`. What it does not allow is `data:` for fonts, because it
does not declare `font-src`.
*/
interface InitResponse {
  response: { totpEnabled: boolean; qrCodePngImage: string; secret: string }
}

export function Configure2FA({
  open,
  onOpenChange,
  token,
  onChanged,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  token: string | null
  onChanged?: (enabled: boolean) => void
}) {
  const [init, setInit] = useState<InitResponse['response'] | null>(null)
  const [totp, setTotp] = useState('')
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setAlert(null)
    setTotp('')
    void (async () => {
      const outcome = await apiRequest<InitResponse>('user/2fa/init', { token })
      if (outcome.kind === 'ok') setInit(outcome.data.response)
    })()
  }, [open, token])

  async function enable() {
    if (totp.length !== 6) {
      setAlert({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the 6-digit OTP that you see in your authenticator app.',
      })
      return
    }
    setBusy(true)
    const outcome = await apiRequest('user/2fa/enable', { method: 'POST', token, body: { totp } })
    setBusy(false)
    if (outcome.kind === 'ok') {
      setAlert({
        type: 'success',
        title: '2FA Enabled!',
        text: 'Two-factor authentication (2FA) was enabled successfully.',
      })
      onChanged?.(true)
      return
    }
    setAlert(noticeFromFailure(outcome))
  }

  async function disable() {
    setBusy(true)
    const outcome = await apiRequest('user/2fa/disable', { method: 'POST', token })
    setBusy(false)
    if (outcome.kind === 'ok') {
      setAlert({
        type: 'success',
        title: '2FA Disabled!',
        text: 'Two-factor authentication (2FA) was disabled successfully.',
      })
      onChanged?.(false)
      return
    }
    setAlert(noticeFromFailure(outcome))
  }

  const enabled = init?.totpEnabled ?? false

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      // The modal's title is the LONG form; "Configure 2FA" is only the user
      // menu's entry (index.html:3761). They are not the same string.
      size="medium"
      title="Configure Two-factor Authentication (2FA)"
      actions={
        <>
          {enabled ? (
            <Button variant="danger" disabled={busy} onClick={() => void disable()}>
              Disable 2FA
            </Button>
          ) : (
            <Button variant="primary" disabled={busy} onClick={() => void enable()}>
              Enable 2FA
            </Button>
          )}
        </>
      }
    >
      <Notifier notice={alert} onClose={() => setAlert(null)} />
      {!enabled && init && (
        <>
          <img
            src={`data:image/png;base64,${init.qrCodePngImage}`}
            alt="QR code for the authenticator app"
            width={200}
            height={200}
            style={{ alignSelf: 'center', background: '#fff', padding: 8, borderRadius: 8 }}
          />
          <LabeledInput label="Secret" mono value={init.secret} readOnly />
          <LabeledInput
            label="OTP"
            mono
            inputMode="numeric"
            maxLength={6}
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
          />
        </>
      )}
    </Dialog>
  )
}
