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
import { Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import { desdeAhora, fechaHora } from '../../lib/fechas'
import { avisoDeFallo } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'
import { Confirmar } from '../../ui/Confirmar'
import { Menu } from '../../ui/Menu'

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
  totpEnabled: boolean
  /** Los grupos de los que el usuario es miembro (auth.js:678-687). */
  memberOfGroups: string[]
  sessionTimeoutSeconds: number
  sessions: SessionRow[]
}

/* `sortTable('tbodyMyProfileMemberOf', 0)`. */
const CLAVES_GRUPO: Claves<string> = { group: (g) => g }

/* `sortTable('tbodyMyProfileActiveSessions', 0..3)`. */
const CLAVES: Claves<Profile['sessions'][number]> = {
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
  const { filas: sesionesVisibles, orden, alternar } = useOrden(CLAVES, profile?.sessions ?? [])
  const grupos = useOrden(CLAVES_GRUPO, profile?.memberOfGroups ?? [])
  const [displayName, setDisplayName] = useState('')
  const [timeout, setTimeoutSeconds] = useState('')
  const [alert, setAlert] = useState<{ type: AlertType; title: string; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [porBorrar, setPorBorrar] = useState<SessionRow | null>(null)

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

  La confirmación es `ui/Confirmar`, la misma que usan «Administration >
  Sessions» y «User Details» para esta misma acción. Aquí se había quedado el
  `confirm()` nativo del navegador.
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
      tamano="ancho"
      title="My Profile"
      acciones={
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
      {/* auth.js:667-674 — en un usuario de SSO el 2FA no lo lleva esta consola. */}
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
        <div className={styles.caption}>Member Of</div>
        {/* La tabla de la consola, no una propia: `ui/Table.module.css`. Este
            módulo tenía la suya con una cuarta densidad de celda y sin el panel
            que la envuelve, así que la misma tabla de sesiones se veía de dos
            maneras según se abriera desde «My Profile» o desde «User Details». */}
        <Tabla
          className={styles.estrecha}
          cabecera={
            <Th campo="group" orden={grupos.orden} onOrdenar={grupos.alternar}>Group</Th>
          }
          vacia={grupos.filas.length === 0}
          vacio="No Group Found"
          columnas={1}
        >
          {grupos.filas.map((g) => (
            <tr key={g}>
              <td>{g}</td>
            </tr>
          ))}
        </Tabla>
        <div className={styles.total}>{`Total Groups: ${profile?.memberOfGroups?.length ?? 0}`}</div>
      </div>

      <div>
        <div className={styles.caption}>Active Sessions</div>
        <Tabla
          cabecera={
            <>
              <Th campo="type" orden={orden} onOrdenar={alternar}>Session</Th>
              <Th campo="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
              <Th campo="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
              {/* Upstream la tiene (`index.html`, tabla de `tbodyMyProfileActiveSessions`:
                  Session · Last Seen · Remote Address · User Agent) y aquí se había
                  perdido: era la única de las tres tablas de sesiones de la consola
                  sin ella, y es la que dice DESDE DÓNDE está abierta cada sesión. */}
              <Th campo="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
              <th className={tbl.celdaAcciones} />
            </>
          }
        >
          {sesionesVisibles.map((row) => (
            <tr key={row.partialToken}>
              <td>
                <CeldaSesion sesion={row} />
              </td>
              <td>
                <CeldaUltimaVez fecha={fechaHora(row.lastSeen)} hace={desdeAhora(row.lastSeen)} />
              </td>
              <td className={styles.mono}>{row.lastSeenRemoteAddress}</td>
              <td>
                <CeldaAgente>{row.lastSeenUserAgent}</CeldaAgente>
              </td>
              <td className={tbl.celdaAcciones}>
                <div className={tbl.acciones}>
                  {/* En un desplegable, como en las otras dos tablas de sesiones
                      y como upstream (`auth.js`, `deleteMySession`). */}
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
        </Tabla>
        <div className={styles.total}>Total Sessions: {profile?.sessions?.length ?? 0}</div>
      </div>

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Session"
        texto={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete Session"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && borrarSesion(porBorrar)}
      />
    </Dialog>
  )
}
