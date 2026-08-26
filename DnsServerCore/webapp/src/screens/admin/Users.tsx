import { useCallback, useEffect, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import {
  createUser,
  deleteUser,
  listUsers,
  resetUserPassword,
  setUser,
  type AdminUser,
} from '../../api/admin'
import type { ClusterState } from '../../api/admin-cluster'
import { UserDetails } from './UserDetails'
import { fechaHora } from './fechas'
import {
  avisoDeFallo,
  Confirmar,
  Etiqueta,
  MRow,
  adminStyles as styles,
  type Aviso,
} from './partes'

/*
`refreshAdminUsers` y las siete acciones de la fila (auth.js:1083-1698).

Cinco de esas siete acciones —guardar el modal, activar, desactivar, quitar el
2FA y resetear la contraseña— salen por el MISMO endpoint `admin/users/set`,
porque el servidor sólo toca los campos que llegan. La sexta y la séptima son
`admin/users/create` y `admin/users/delete`.

Dos asimetrías de upstream que se replican tal cual:

  · Desactivar pide confirmación; ACTIVAR no.
  · «Reset Password» y «Disable 2FA» sólo se ofrecen a un usuario local, y
    «Disable 2FA» además sólo si lo tiene puesto (auth.js:1150-1157).
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onAviso: (a: Aviso) => void
}

type Accion =
  | { tipo: 'disable'; user: AdminUser }
  | { tipo: '2fa'; user: AdminUser }
  | { tipo: 'delete'; user: AdminUser }

export function Users({ token, cluster, onAviso }: Props) {
  const [usuarios, setUsuarios] = useState<AdminUser[]>([])
  const [cargando, setCargando] = useState(true)
  const [anadir, setAnadir] = useState(false)
  const [reset, setReset] = useState<string | null>(null)
  const [detalle, setDetalle] = useState<string | null>(null)
  const [accion, setAccion] = useState<Accion | null>(null)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await listUsers(token)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setUsuarios([])
      onAviso(avisoDeFallo(outcome))
      return
    }
    setUsuarios(outcome.data.response.users)
  }, [token, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  function reemplazar(u: AdminUser) {
    setUsuarios((lista) => lista.map((x) => (x.username === u.username ? u : x)))
  }

  /** Cambiar el nombre de usuario desde el modal deja la fila sin pareja por
   *  `username`; upstream la sustituye por posición. Aquí se hace por índice
   *  del usuario que se abrió, que es lo mismo. */
  function reemplazarPor(anterior: string, u: AdminUser) {
    setUsuarios((lista) => lista.map((x) => (x.username === anterior ? u : x)))
  }

  async function cambiar(u: AdminUser, body: Record<string, string>, aviso: Aviso) {
    setAccion(null)
    const outcome = await setUser(token, { user: u.username, ...body })
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    reemplazar(outcome.data.response)
    onAviso(aviso)
  }

  async function borrar(u: AdminUser) {
    setAccion(null)
    const outcome = await deleteUser(token, u.username)
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setUsuarios((lista) => lista.filter((x) => x.username !== u.username))
    onAviso({ type: 'success', title: 'User Deleted!', text: 'User account was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        seccion="Administration"
        titulo="Users"
        acciones={<><Button variant="primary" onClick={() => setAnadir(true)}>
            Add User
          </Button></>}
      />

      {cargando ? (
        <div className={styles.loading}>Loading…</div>
      ) : (
        <>
          <div className={styles.tablaWrap}>
            <table className={styles.tabla}>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Type</th>
                  <th>2FA Status</th>
                  <th>Status</th>
                  <th>Recent Login</th>
                  <th>Previous Login</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {usuarios.map((u) => (
                  <tr key={u.username}>
                    <td>
                      <button
                        type="button"
                        className={styles.link}
                        onClick={() => setDetalle(u.username)}
                      >
                        {u.username}
                      </button>
                    </td>
                    <td>{u.displayName}</td>
                    <td>{u.isSsoUser ? 'Remote/SSO' : 'Local'}</td>
                    <td>
                      {u.isSsoUser ? (
                        <Etiqueta tipo="info">SSO Managed</Etiqueta>
                      ) : u.totpEnabled ? (
                        <Etiqueta tipo="success">Enabled</Etiqueta>
                      ) : (
                        <Etiqueta tipo="default">Disabled</Etiqueta>
                      )}
                    </td>
                    <td>
                      {u.disabled ? (
                        <Etiqueta tipo="default">Disabled</Etiqueta>
                      ) : (
                        <Etiqueta tipo="success">Enabled</Etiqueta>
                      )}
                    </td>
                    <td className={styles.mono}>
                      {`${fechaHora(u.recentSessionLoggedOn)} from ${u.recentSessionRemoteAddress}`}
                    </td>
                    <td className={styles.mono}>
                      {`${fechaHora(u.previousSessionLoggedOn)} from ${u.previousSessionRemoteAddress}`}
                    </td>
                    <td>
                      <div className={styles.rowacts}>
                        <button type="button" className={styles.ib} onClick={() => setDetalle(u.username)}>
                          View Details
                        </button>
                        {u.disabled ? (
                          <button
                            type="button"
                            className={styles.ib}
                            onClick={() =>
                              void cambiar(u, { disabled: 'false' }, {
                                type: 'success',
                                title: 'User Enabled!',
                                text: `User [${u.username}] account was enabled successfully.`,
                              })
                            }
                          >
                            Enable
                          </button>
                        ) : (
                          <button
                            type="button"
                            className={styles.ib}
                            onClick={() => setAccion({ tipo: 'disable', user: u })}
                          >
                            Disable
                          </button>
                        )}
                        {!u.isSsoUser && (
                          <button
                            type="button"
                            className={styles.ib}
                            onClick={() => setReset(u.username)}
                          >
                            Reset Password
                          </button>
                        )}
                        {!u.isSsoUser && u.totpEnabled && (
                          <button
                            type="button"
                            className={styles.ib}
                            onClick={() => setAccion({ tipo: '2fa', user: u })}
                          >
                            Disable 2FA
                          </button>
                        )}
                        <button
                          type="button"
                          className={`${styles.ib} ${styles.ibDanger}`}
                          onClick={() => setAccion({ tipo: 'delete', user: u })}
                        >
                          Delete User
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.count}>
            <span>{`Total Users: ${usuarios.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={accion?.tipo === 'disable'}
        titulo="Disable User"
        texto={`Are you sure you want to disable the user [${accion?.user.username ?? ''}] account?`}
        etiqueta="Disable"
        onCerrar={() => setAccion(null)}
        onConfirmar={() =>
          accion?.tipo === 'disable' &&
          void cambiar(accion.user, { disabled: 'true' }, {
            type: 'success',
            title: 'User Disabled!',
            text: `User [${accion.user.username}] account was disabled successfully.`,
          })
        }
      />

      <Confirmar
        abierto={accion?.tipo === '2fa'}
        titulo="Disable 2FA"
        texto={`Are you sure you want to disable Two-factor authentication (2FA) for user [${accion?.user.username ?? ''}] ?`}
        etiqueta="Disable"
        onCerrar={() => setAccion(null)}
        onConfirmar={() =>
          accion?.tipo === '2fa' &&
          void cambiar(accion.user, { totpEnabled: 'false' }, {
            type: 'success',
            title: '2FA Disabled!',
            text: `Two-factor authentication was disabled successfully for user [${accion.user.username}].`,
          })
        }
      />

      <Confirmar
        abierto={accion?.tipo === 'delete'}
        titulo="Delete User"
        texto={`Are you sure you want to delete the user [${accion?.user.username ?? ''}] account?`}
        etiqueta="Delete"
        onCerrar={() => setAccion(null)}
        onConfirmar={() => accion?.tipo === 'delete' && void borrar(accion.user)}
      />

      <AnadirUsuario
        abierto={anadir}
        token={token}
        onCerrar={() => setAnadir(false)}
        onAnadido={(u) => {
          setUsuarios((lista) => [u, ...lista])
          onAviso({ type: 'success', title: 'User Added!', text: 'User was added successfully.' })
        }}
      />

      {reset != null && (
        <ResetearContrasena
          username={reset}
          token={token}
          onCerrar={() => setReset(null)}
          onAviso={onAviso}
        />
      )}

      {detalle != null && (
        <UserDetails
          abierto
          username={detalle}
          token={token}
          cluster={cluster}
          onCerrar={() => setDetalle(null)}
          alGuardar={(u) => reemplazarPor(detalle, u)}
          onAviso={onAviso}
        />
      )}
    </>
  )
}

/* `addUser` (auth.js:1178). El orden de las cuatro validaciones es contrato. */
function AnadirUsuario({
  abierto,
  token,
  onCerrar,
  onAnadido,
}: {
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onAnadido: (u: AdminUser) => void
}) {
  const [displayName, setDisplayName] = useState('')
  const [usuario, setUsuario] = useState('')
  const [pass, setPass] = useState('')
  const [confirmar, setConfirmar] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setDisplayName('')
    setUsuario('')
    setPass('')
    setConfirmar('')
  }, [abierto])

  async function anadir() {
    if (usuario === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter an username to add user.' })
      return
    }
    if (pass === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a password to add user.' })
      return
    }
    if (confirmar === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter confirm password.' })
      return
    }
    if (pass !== confirmar) {
      setAviso({
        type: 'warning',
        title: 'Mismatch!',
        text: 'Passwords do not match. Please try again.',
      })
      return
    }

    setOcupado(true)
    const outcome = await createUser(token, displayName, usuario, pass)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onAnadido(outcome.data.response)
    onCerrar()
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title="Add User"
      footer={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void anadir()}>
            Add
          </Button>
          <Button onClick={onCerrar}>Close</Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <MRow label="Display Name">
        {(id) => (
          <Input
            id={id}
            placeholder="display name"
            maxLength={255}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Username">
        {(id) => (
          <Input
            id={id}
            placeholder="username"
            maxLength={255}
            value={usuario}
            onChange={(e) => setUsuario(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            placeholder="password"
            maxLength={255}
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Confirm Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            placeholder="confirm password"
            maxLength={255}
            value={confirmar}
            onChange={(e) => setConfirmar(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/*
`showResetUserPasswordModal` / `resetUserPassword` (auth.js:1546-1627).
Upstream REUTILIZA el modal «Change Password» cambiando su título a «Reset
Password», escondiendo la contraseña actual y el OTP, y renombrando el botón a
«Reset». El aviso de éxito sale en la PÁGINA, porque el modal ya se ha cerrado.
*/
function ResetearContrasena({
  username,
  token,
  onCerrar,
  onAviso,
}: {
  username: string
  token: string | null
  onCerrar: () => void
  onAviso: (a: Aviso) => void
}) {
  const [nueva, setNueva] = useState('')
  const [confirmar, setConfirmar] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function guardar() {
    if (nueva === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter new password.' })
      return
    }
    if (confirmar === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter confirm password.' })
      return
    }
    if (nueva !== confirmar) {
      setAviso({
        type: 'warning',
        title: 'Mismatch!',
        text: 'Passwords do not match. Please try again.',
      })
      return
    }

    setOcupado(true)
    const outcome = await resetUserPassword(token, username, nueva)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onCerrar()
    onAviso({ type: 'success', title: 'Password Reset!', text: 'Password was reset successfully.' })
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Reset Password"
      footer={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void guardar()}>
            Reset
          </Button>
          <Button onClick={onCerrar}>Close</Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <MRow label="Username">{(id) => <Input id={id} value={username} readOnly />}</MRow>
      <MRow label="New Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            maxLength={255}
            value={nueva}
            onChange={(e) => setNueva(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Confirm Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            maxLength={255}
            value={confirmar}
            onChange={(e) => setConfirmar(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}
