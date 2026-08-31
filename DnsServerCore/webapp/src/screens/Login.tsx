import { useEffect, useRef, useState } from 'react'
import { apiRequest } from '../api/client'
import { getStatus } from '../api/status'
import { type AlertType } from '../ui/Alert'
import { Button } from '../ui/Button'
import { LabeledInput } from '../ui/Field'
import { ForgotPassword } from './modals/ForgotPassword'
import styles from './Login.module.css'
import { urlPublica } from '../app/base'
import { PieDeEnlaces } from '../ui/PieDeEnlaces'
import { Notifier } from '../ui/Avisador'

/*
The login screen. A replica of `login()` in
upstream/master:DnsServerCore/www/js/auth.js:207-297.

The alert texts are upstream LITERALS and they are contract: changing them would
be changing behaviour.
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
  const [olvido, setOlvido] = useState(false)
  const [alert, setAlert] = useState<AlertState | null>(initialAlert ?? null)
  // The SSO button is only drawn if the server says it is enabled
  // (main.js:48-56). By default NOT: SSO is not assumed.
  const [ssoEnabled, setSsoEnabled] = useState(false)

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

  /** Returns to the login after 30 s on the OTP panel, just like upstream. */
  function armOtpTimer() {
    clearOtpTimer()
    timerRef.current = setTimeout(() => {
      setOtpVisible(false)
      setTotp('')
    }, OTP_TIMEOUT_INTERVAL)
  }

  useEffect(() => clearOtpTimer, [])

  /*
  main.js:48-60 — on showing the login, `api/status` is queried, and it decides
  two things: whether the SSO button shows, and whether the install still has the
  factory credentials, in which case it **logs itself in** with admin/admin. A
  failed auto-login leaves no alert: it falls back to the form in silence.
  */
  useEffect(() => {
    let cancelled = false
    void (async () => {
      const st = await getStatus()
      if (cancelled || !st) return
      setSsoEnabled(st.ssoEnabled)
      if (st.hasDefaultCredentials) void submit(undefined, { user: 'admin', pass: 'admin', auto: true })
    })()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submit(
    totpOverride?: string,
    auto?: { user: string; pass: string; auto: true },
  ) {
    const totpValue = totpOverride ?? totp
    const enteredUser = auto ? auto.user : user
    const enteredPass = auto ? auto.pass : pass

    if (enteredUser === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter an username.' })
      userRef.current?.focus()
      return
    }

    if (enteredPass === '') {
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
        user: enteredUser.toLowerCase(),
        pass: enteredPass,
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
      // auth.js:263 — logging in with the factory credentials and no 2FA forces a
      // password change before going on.
      const forcePasswordChange =
        !session.totpEnabled && enteredUser.toLowerCase() === 'admin' && enteredPass === 'admin'
      onSuccess(session, { forcePasswordChange })
      return
    }

    // auth.js:281 — if the attempt was automatic, the failure is swallowed: the
    // form is left clean instead of an alert the user did not cause.
    if (auto) {
      userRef.current?.focus()
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

  /** auth.js:70-74 — on reaching 6 characters it submits itself. */
  function onTotpInput(value: string) {
    setTotp(value)
    if (value.length === 6) void submit(value)
  }

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.brand}>
          <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={28} height={28} />
          <span className={styles.name}>Technitium DNS Server</span>
        </div>

        <Notifier notice={alert} onClose={() => setAlert(null)} />

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

        {/* In upstream the link goes BEFORE the SSO block, and the "or login
            with" only appears if there is SSO (index.html:119-124). */}
        <div className={styles.sso}>
          <button type="button" className={styles.link} onClick={() => setOlvido(true)}>
            Forgot Password?
          </button>

          {ssoEnabled && (
            <>
              <div className={styles.oLogin}>or login with</div>
              <a className={styles.ssoLink} href="sso/login">
                Sign in with SSO
              </a>
            </>
          )}
        </div>
      </div>

      {/* Upstream's footer shows on its login screen too, because it hangs off
          the `body` and not the panel. See `app/pie.ts`. */}
      <PieDeEnlaces className={styles.footer} />

      <ForgotPassword open={olvido} onOpenChange={setOlvido} />
    </div>
  )
}
