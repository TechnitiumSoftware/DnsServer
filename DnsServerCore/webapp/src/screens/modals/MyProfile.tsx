import { useEffect, useState } from 'react'
import { apiRequest } from '../../api/client'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { deleteSession, type SessionRow } from '../../api/user'
import styles from './MyProfile.module.css'

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
  sessions: SessionRow[]
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
  const [reloadKey, setReloadKey] = useState(0)

  // Limpiar el aviso SÓLO al abrir. Si se limpiara también al recargar, el
  // mensaje de «sesión borrada» se perdería, porque borrar dispara una recarga.
  useEffect(() => {
    if (open) setAlert(null)
  }, [open])

  useEffect(() => {
    if (!open) return
    void (async () => {
      const outcome = await apiRequest<{ response: Profile }>('user/profile/get', { token })
      if (outcome.kind === 'ok') {
        setProfile(outcome.data.response)
        setDisplayName(outcome.data.response.displayName)
        setTimeoutSeconds(String(outcome.data.response.sessionTimeoutSeconds))
      }
    })()
  }, [open, token, reloadKey])

  /*
  auth.js:795-838 — antes de borrar una sesión upstream pide confirmación con
  este texto exacto, y el mensaje de éxito también es literal.
  */
  async function borrarSesion(row: SessionRow) {
    if (!window.confirm(`Are you sure you want to delete the session [${row.partialToken}] ?`)) return
    const outcome = await deleteSession(token, row.partialToken)
    if (outcome.kind === 'ok') {
      setAlert({
        type: 'success',
        title: 'Session Deleted!',
        text: 'The user session was deleted successfully.',
      })
      setReloadKey((k) => k + 1)
      return
    }
    setAlert({
      type: 'danger',
      title: 'Error!',
      text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
    })
  }

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

      <div>
        <div className={styles.caption}>Active Sessions</div>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Type</th>
              <th>Last Seen</th>
              <th>Address</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(profile?.sessions ?? []).map((row) => (
              <tr key={row.partialToken}>
                <td>
                  {row.type}
                  {row.tokenName ? ` (${row.tokenName})` : ''}
                  {row.isCurrentSession && <span className={styles.current}>current</span>}
                </td>
                <td className={styles.mono}>{row.lastSeen}</td>
                <td className={styles.mono}>{row.lastSeenRemoteAddress}</td>
                <td>
                  <Button
                    variant="danger"
                    onClick={() => void borrarSesion(row)}
                    aria-label={`Delete session ${row.partialToken}`}
                  >
                    Delete Session
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className={styles.total}>Total Sessions: {profile?.sessions?.length ?? 0}</div>
      </div>
    </Dialog>
  )
}
