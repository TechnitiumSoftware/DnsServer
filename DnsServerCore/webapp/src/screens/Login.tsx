import { useEffect, useRef, useState } from 'react'
import { apiRequest } from '../api/client'
import { Alert, type AlertType } from '../ui/Alert'
import { Button } from '../ui/Button'
import { LabeledInput } from '../ui/Field'
import styles from './Login.module.css'

/*
Pantalla de login. Réplica de `login()` en
upstream/master:DnsServerCore/www/js/auth.js:207-297.

Los textos de aviso son LITERALES de upstream y son contrato: cambiarlos sería
cambiar comportamiento.
*/

export const OTP_TIMEOUT_INTERVAL = 30_000

export interface Session {
  token: string
  displayName: string
  username: string
  totpEnabled: boolean
  info?: { dnsServerDomain: string; version: string; uptimestamp: string }
}

interface AlertState {
  type: AlertType
  title: string
  text: string
}

export function Login({
  onSuccess,
  initialAlert,
}: {
  onSuccess: (session: Session, opts: { forcePasswordChange: boolean }) => void
  initialAlert?: AlertState
}) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [totp, setTotp] = useState('')
  const [otpVisible, setOtpVisible] = useState(false)
  const [busy, setBusy] = useState(false)
  const [alert, setAlert] = useState<AlertState | null>(initialAlert ?? null)

  const userRef = useRef<HTMLInputElement>(null)
  const passRef = useRef<HTMLInputElement>(null)
  const otpRef = useRef<HTMLInputElement>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function clearOtpTimer() {
    if (timerRef.current != null) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }

  /** Vuelve al login pasados 30 s en el panel OTP, igual que upstream. */
  function armOtpTimer() {
    clearOtpTimer()
    timerRef.current = setTimeout(() => {
      setOtpVisible(false)
      setTotp('')
    }, OTP_TIMEOUT_INTERVAL)
  }

  useEffect(() => clearOtpTimer, [])

  async function submit(totpOverride?: string) {
    const totpValue = totpOverride ?? totp

    if (user === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter an username.' })
      userRef.current?.focus()
      return
    }

    if (pass === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter a password.' })
      passRef.current?.focus()
      return
    }

    if (otpVisible && totpValue.length !== 6) {
      setAlert({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the 6-digit OTP that you see in your authenticator app.',
      })
      otpRef.current?.focus()
      armOtpTimer()
      return
    }

    setBusy(true)
    const outcome = await apiRequest<Session & { status: string }>('user/login', {
      method: 'POST',
      body: {
        user: user.toLowerCase(),
        pass,
        totp: totpValue,
        includeInfo: 'true',
      },
    })
    setBusy(false)

    if (outcome.kind === 'two-factor-required') {
      setOtpVisible(true)
      setTotp('')
      armOtpTimer()
      window.setTimeout(() => otpRef.current?.focus(), 0)
      return
    }

    if (outcome.kind === 'ok') {
      clearOtpTimer()
      const session = outcome.data as Session
      // auth.js:263 — entrar con las credenciales de fábrica y sin 2FA obliga a
      // cambiar la contraseña antes de seguir.
      const forcePasswordChange =
        !session.totpEnabled && user.toLowerCase() === 'admin' && pass === 'admin'
      onSuccess(session, { forcePasswordChange })
      return
    }

    const message =
      outcome.kind === 'invalid-token'
        ? 'Invalid token or session expired.'
        : outcome.message
    setAlert({ type: 'danger', title: 'Error!', text: message })

    if (otpVisible) {
      setTotp('')
      otpRef.current?.focus()
      armOtpTimer()
    } else {
      userRef.current?.focus()
    }
  }

  /** auth.js:70-74 — al alcanzar los 6 caracteres se envía solo. */
  function onTotpInput(value: string) {
    setTotp(value)
    if (value.length === 6) void submit(value)
  }

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.brand}>
          <span className={styles.mark}>T</span>
          <span className={styles.name}>Technitium DNS Server</span>
        </div>

        {alert && (
          <div className={styles.alertSlot}>
            <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
              {alert.text}
            </Alert>
          </div>
        )}

        <form
          className={styles.form}
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <LabeledInput
            label="Username"
            ref={userRef}
            value={user}
            autoComplete="username"
            onChange={(e) => setUser(e.target.value)}
          />
          <LabeledInput
            label="Password"
            type="password"
            ref={passRef}
            value={pass}
            disabled={otpVisible}
            autoComplete="current-password"
            onChange={(e) => setPass(e.target.value)}
          />
          {otpVisible && (
            <LabeledInput
              label="OTP"
              mono
              inputMode="numeric"
              maxLength={6}
              ref={otpRef}
              value={totp}
              autoComplete="one-time-code"
              onChange={(e) => onTotpInput(e.target.value)}
            />
          )}
          <Button type="submit" variant="primary" disabled={busy}>
            Login
          </Button>
        </form>

        <div className={styles.sso}>
          <a className={styles.ssoLink} href="sso/login">
            Sign in with SSO
          </a>
        </div>
      </div>
    </div>
  )
}
