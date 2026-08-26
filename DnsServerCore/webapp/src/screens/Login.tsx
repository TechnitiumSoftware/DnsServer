import { useEffect, useRef, useState } from 'react'
import { apiRequest } from '../api/client'
import { getStatus } from '../api/status'
import { Alert, type AlertType } from '../ui/Alert'
import { Button } from '../ui/Button'
import { LabeledInput } from '../ui/Field'
import { ForgotPassword } from './modals/ForgotPassword'
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
  const [olvido, setOlvido] = useState(false)
  const [alert, setAlert] = useState<AlertState | null>(initialAlert ?? null)
  // El botón de SSO sólo se pinta si el servidor dice que está habilitado
  // (main.js:48-56). Por defecto NO: no se asume que hay SSO.
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

  /** Vuelve al login pasados 30 s en el panel OTP, igual que upstream. */
  function armOtpTimer() {
    clearOtpTimer()
    timerRef.current = setTimeout(() => {
      setOtpVisible(false)
      setTotp('')
    }, OTP_TIMEOUT_INTERVAL)
  }

  useEffect(() => clearOtpTimer, [])

  /*
  main.js:48-60 — al mostrar el login se consulta `api/status`, que decide dos
  cosas: si se ve el botón de SSO, y si la instalación todavía tiene las
  credenciales de fábrica, en cuyo caso **entra sola** con admin/admin.
  Un auto-login fallido no deja alerta: se cae al formulario en silencio.
  */
  useEffect(() => {
    let cancelado = false
    void (async () => {
      const st = await getStatus()
      if (cancelado || !st) return
      setSsoEnabled(st.ssoEnabled)
      if (st.hasDefaultCredentials) void submit(undefined, { user: 'admin', pass: 'admin', auto: true })
    })()
    return () => {
      cancelado = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submit(
    totpOverride?: string,
    auto?: { user: string; pass: string; auto: true },
  ) {
    const totpValue = totpOverride ?? totp
    const usuario = auto ? auto.user : user
    const clave = auto ? auto.pass : pass

    if (usuario === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter an username.' })
      userRef.current?.focus()
      return
    }

    if (clave === '') {
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
        user: usuario.toLowerCase(),
        pass: clave,
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
        !session.totpEnabled && usuario.toLowerCase() === 'admin' && clave === 'admin'
      onSuccess(session, { forcePasswordChange })
      return
    }

    // auth.js:281 — si el intento era automático, el fallo se traga: se deja el
    // formulario limpio en vez de una alerta que el usuario no ha provocado.
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

        {/* En upstream el enlace va ANTES del bloque de SSO, y el «or login
            with» sólo aparece si hay SSO (index.html:119-124). */}
        <div className={styles.sso}>
          <button type="button" className={styles.enlace} onClick={() => setOlvido(true)}>
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

      <ForgotPassword open={olvido} onOpenChange={setOlvido} />
    </div>
  )
}
