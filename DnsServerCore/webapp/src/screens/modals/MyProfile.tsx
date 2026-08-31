import { useEffect, useState } from 'react'
import { apiRequest } from '../../api/client'
import { type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { LabeledInput } from '../../ui/Field'
import { CeldaAgente, CeldaSesion, CeldaUltimaVez } from '../../ui/Sesion'
import { deleteSession, type SessionRow } from '../../api/user'
import styles from './MyProfile.module.css'
import tbl from '../../ui/Table.module.css'
import { Th, useOrden, type Keys, Table } from '../../ui/Table'
import { desdeAhora, fechaHora } from '../../lib/fechas'
import { avisoDeFallo } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'
import { Confirmar } from '../../ui/Confirmar'
import { Menu } from '../../ui/Menu'

/*
A replica of `showMyProfileModal` / `saveMyProfile` (auth.js:642-794).

Two details of the contract: the display name is DISABLED for SSO users, and that
is why `displayName` is only sent if the field is not disabled (auth.js:756-761).
The user type is shown as "Remote/SSO" or "Local".
*/
interface Profile {
  displayName: string
  username: string
  isSsoUser: boolean
  totpEnabled: boolean
  /** The groups the user is a member of (auth.js:678-687). */
  memberOfGroups: string[]
  sessionTimeoutSeconds: number
  sessions: SessionRow[]
}

/* `sortTable('tbodyMyProfileMemberOf', 0)`. */
const CLAVES_GRUPO: Keys<string> = { group: (g) => g }

/* `sortTable('tbodyMyProfileActiveSessions', 0..3)`. */
const KEYS: Keys<Profile['sessions'][number]> = {
  type: (r) => `${r.type}${r.tokenName ? ` (${r.tokenName})` : ''}${r.isCurrentSession ? ' current' : ''}`,
  lastSeen: (r) => fechaHora(r.lastSeen),
  address: (r) => r.lastSeenRemoteAddress,
  agent: (r) => r.lastSeenUserAgent,
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
  const { rows: sesionesVisibles, orden, alternar } = useOrden(KEYS, profile?.sessions ?? [])
  const groups = useOrden(CLAVES_GRUPO, profile?.memberOfGroups ?? [])
  const [displayName, setDisplayName] = useState('')
  const [timeout, setTimeoutSeconds] = useState('')
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [porBorrar, setPorBorrar] = useState<SessionRow | null>(null)

  // Clear the alert ONLY on opening. Were it cleared on reload too, the
  // "session deleted" message would be lost, since deleting triggers a reload.
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
  auth.js:795-838 — before deleting a session upstream asks for confirmation
  with this exact text, and the success message is literal too.

  The confirmation is `ui/Confirmar`, the same one "Administration > Sessions"
  and "User Details" use for this very action. Here the browser's native
  `confirm()` had been left behind.
  */
  async function borrarSesion(row: SessionRow) {
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
    setAlert(avisoDeFallo(outcome))
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
    setAlert(avisoDeFallo(outcome))
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="wide"
      title="My Profile"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={alert} onCerrar={() => setAlert(null)} />
      <LabeledInput label="Username" value={profile?.username ?? ''} readOnly />
      <LabeledInput label="User Type" value={profile?.isSsoUser ? 'Remote/SSO' : 'Local'} readOnly />
      {/* auth.js:667-674 — on an SSO user the 2FA is not this console's business. */}
      <LabeledInput
        label="2FA Status"
        value={
          profile == null
            ? ''
            : profile.isSsoUser
              ? 'SSO Managed'
              : profile.totpEnabled
                ? 'Enabled'
                : 'Disabled'
        }
        readOnly
      />
      <LabeledInput
        label="Display Name"
        placeholder="display name"
        value={displayName}
        disabled={profile?.isSsoUser ?? false}
        onChange={(e) => setDisplayName(e.target.value)}
      />
      <LabeledInput
        label="Session Timeout"
        placeholder="1800"
        mono
        value={timeout}
        onChange={(e) => setTimeoutSeconds(e.target.value)}
      />

      <div>
        <div className={styles.caption}>Member Of</div>
        {/* The console's table, not one of its own: `ui/Table.module.css`. This
            module had its own with a fourth cell density and without the panel
            that wraps it, so the same sessions table looked two different ways
            depending on whether it opened from "My Profile" or "User Details". */}
        <Table
          className={styles.estrecha}
          header={
            <Th field="group" orden={groups.orden} onOrdenar={groups.alternar}>Group</Th>
          }
          isEmpty={groups.rows.length === 0}
          emptyText="No Group Found"
          columnas={1}
        >
          {groups.rows.map((g) => (
            <tr key={g}>
              <td>{g}</td>
            </tr>
          ))}
        </Table>
        <div className={styles.total}>{`Total Groups: ${profile?.memberOfGroups?.length ?? 0}`}</div>
      </div>

      <div>
        <div className={styles.caption}>Active Sessions</div>
        <Table
          header={
            <>
              <Th field="type" orden={orden} onOrdenar={alternar}>Session</Th>
              <Th field="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
              <Th field="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
              {/* Upstream has it (`index.html`, the `tbodyMyProfileActiveSessions`
                  table: Session · Last Seen · Remote Address · User Agent) and here
                  it had been lost: it was the only one of the console's three
                  sessions tables without it, and it is the one that says WHERE each
                  session is open from. */}
              <Th field="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
              <th className={tbl.celdaAcciones} />
            </>
          }
        >
          {sesionesVisibles.map((row) => (
            <tr key={row.partialToken}>
              <td>
                <CeldaSesion session={row} />
              </td>
              <td>
                <CeldaUltimaVez date={fechaHora(row.lastSeen)} hace={desdeAhora(row.lastSeen)} />
              </td>
              <td className={styles.mono}>{row.lastSeenRemoteAddress}</td>
              <td>
                <CeldaAgente>{row.lastSeenUserAgent}</CeldaAgente>
              </td>
              <td className={tbl.celdaAcciones}>
                <div className={tbl.actions}>
                  {/* In a dropdown, as in the other two sessions tables and as in
                      upstream (`auth.js`, `deleteMySession`). */}
                  <Menu etiqueta={`Actions for ${row.partialToken}`}>
                    {(cerrar) => (
                      <button
                        type="button"
                        data-variant="danger"
                        onClick={() => { cerrar(); setPorBorrar(row) }}
                      >
                        Delete Session
                      </button>
                    )}
                  </Menu>
                </div>
              </td>
            </tr>
          ))}
        </Table>
        <div className={styles.total}>Total Sessions: {profile?.sessions?.length ?? 0}</div>
      </div>

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Session"
        text={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete Session"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && borrarSesion(porBorrar)}
      />
    </Dialog>
  )
}
