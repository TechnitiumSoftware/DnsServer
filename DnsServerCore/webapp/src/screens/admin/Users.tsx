import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
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
  MRow,
  adminStyles as styles,
  type Aviso,
} from './partes'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu, Separador } from '../../ui/Menu'
import { neverUsed } from '../../api/zones'
import { Avisador } from '../../ui/Avisador'

/*
`refreshAdminUsers` and the row's seven actions (auth.js:1083-1698).

Five of those seven actions —saving the modal, enabling, disabling, clearing the
2FA and resetting the password— go out through the SAME `admin/users/set`
endpoint, because the server only touches the fields that arrive. The sixth and
seventh are `admin/users/create` and `admin/users/delete`.

Two asymmetries of upstream's that are replicated as they are:

  · Disabling asks for confirmation; ENABLING does not.
  · "Reset Password" and "Disable 2FA" are only offered to a local user, and
    "Disable 2FA" only if they have it on (auth.js:1150-1157).
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onAviso: (a: Aviso) => void
}

type Action =
  | { tipo: 'disable'; user: AdminUser }
  | { tipo: '2fa'; user: AdminUser }
  | { tipo: 'delete'; user: AdminUser }

/** The date of a login, or "Never" if it is .NET's sentinel. */
function acceso(iso: string, address: string): string {
  return neverUsed(iso) ? 'Never' : `${fechaHora(iso)} from ${address}`
}

/* `sortTable('tbodyAdminUsers', 0..6)`. */
const KEYS: Keys<AdminUser> = {
  username: (u) => u.username,
  display: (u) => u.displayName,
  type: (u) => (u.isSsoUser ? 'Remote/SSO' : 'Local'),
  totp: (u) => (u.isSsoUser ? 'SSO Managed' : u.totpEnabled ? 'Enabled' : 'Disabled'),
  status: (u) => (u.disabled ? 'Disabled' : 'Enabled'),
  recent: (u) => acceso(u.recentSessionLoggedOn, u.recentSessionRemoteAddress),
  previous: (u) => acceso(u.previousSessionLoggedOn, u.previousSessionRemoteAddress),
}

export function Users({ token, cluster, onAviso }: Props) {
  const [users, setUsuarios] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [anadir, setAnadir] = useState(false)
  const [reset, setReset] = useState<string | null>(null)
  const [detalle, setDetalle] = useState<string | null>(null)
  const [action, setAction] = useState<Action | null>(null)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await listUsers(token)
    setLoading(false)

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

  const { rows: usuariosVisibles, orden, alternar } = useOrden(KEYS, users)

  function reemplazar(u: AdminUser) {
    setUsuarios((list) => list.map((x) => (x.username === u.username ? u : x)))
  }

  /** Changing the username from the modal leaves the row with no match by
   *  `username`; upstream replaces it by position. Here it is done by the index
   *  of the user that was opened, which is the same thing. */
  function reemplazarPor(previous: string, u: AdminUser) {
    setUsuarios((list) => list.map((x) => (x.username === previous ? u : x)))
  }

  async function cambiar(u: AdminUser, body: Record<string, string>, aviso: Aviso) {
    setAction(null)
    const outcome = await setUser(token, { user: u.username, ...body })
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    reemplazar(outcome.data.response)
    onAviso(aviso)
  }

  async function borrar(u: AdminUser) {
    setAction(null)
    const outcome = await deleteUser(token, u.username)
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setUsuarios((list) => list.filter((x) => x.username !== u.username))
    onAviso({ type: 'success', title: 'User Deleted!', text: 'User account was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        titulo="Users"
        actions={<><Button variant="primary" onClick={() => setAnadir(true)}>
            Add User
          </Button></>}
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          <Table
            header={
              <>
                <Th field="username" orden={orden} onOrdenar={alternar}>Username</Th>
                <Th field="display" orden={orden} onOrdenar={alternar}>Display Name</Th>
                <Th field="type" orden={orden} onOrdenar={alternar}>Type</Th>
                <Th field="totp" orden={orden} onOrdenar={alternar}>2FA Status</Th>
                <Th field="status" orden={orden} onOrdenar={alternar}>Status</Th>
                <Th field="recent" orden={orden} onOrdenar={alternar}>Recent Login</Th>
                <Th field="previous" orden={orden} onOrdenar={alternar}>Previous Login</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            isEmpty={usuariosVisibles.length === 0}
            emptyText="No User Found"
            columnas={8}
          >
            {usuariosVisibles.map((u) => (
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
                    <Tag tone="info">SSO Managed</Tag>
                  ) : u.totpEnabled ? (
                    <Tag tone="ok">Enabled</Tag>
                  ) : (
                    <Tag>Disabled</Tag>
                  )}
                </td>
                <td>
                  {u.disabled ? (
                    <Tag>Disabled</Tag>
                  ) : (
                    <Tag tone="ok">Enabled</Tag>
                  )}
                </td>
                {/*
                Upstream formats the date without checking whether it is .NET's
                minimum (auth.js:1141), so for a user who has never logged in it
                shows "0000-12-31 23:45:16 from 0.0.0.0" —year zero, because it
                converts to local time a date older than time zones— and an
                address that does not exist. That is not a datum: it is a
                sentinel value leaking onto the screen. It says "Never", which is
                what it means, just as was done with the DNSSEC column.
                */}
                <td className={styles.mono}>{acceso(u.recentSessionLoggedOn, u.recentSessionRemoteAddress)}</td>
                <td className={styles.mono}>{acceso(u.previousSessionLoggedOn, u.previousSessionRemoteAddress)}</td>
                <td className={tbl.celdaAcciones}>
                  <div className={tbl.actions}>
                    <AccionFila
                      icono="ficha"
                      name="View Details"
                      onClick={() => setDetalle(u.username)}
                    />
                    <AccionFila
                      icono="energia"
                      name={u.disabled ? 'Enable User' : 'Disable User'}
                      onClick={() =>
                        u.disabled
                          ? void cambiar(u, { disabled: 'false' }, {
                              type: 'success',
                              title: 'User Enabled!',
                              text: `User [${u.username}] account was enabled successfully.`,
                            })
                          : setAction({ tipo: 'disable', user: u })
                      }
                    />
                    <Menu etiqueta={`Actions for ${u.username}`}>
                      {(cerrar) => (
                        <>
                          {!u.isSsoUser && (
                            <button type="button" onClick={() => { cerrar(); setReset(u.username) }}>
                              Reset Password
                            </button>
                          )}
                          {!u.isSsoUser && u.totpEnabled && (
                            <button type="button" onClick={() => { cerrar(); setAction({ tipo: '2fa', user: u }) }}>
                              Disable 2FA
                            </button>
                          )}
                          <Separador />
                          <button type="button" data-variant="danger" onClick={() => { cerrar(); setAction({ tipo: 'delete', user: u }) }}>
                            Delete User
                          </button>
                        </>
                      )}
                    </Menu>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
          <div className={styles.count}>
            <span>{`Total Users: ${users.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={action?.tipo === 'disable'}
        titulo="Disable User"
        text={`Are you sure you want to disable the user [${action?.user.username ?? ''}] account?`}
        etiqueta="Disable"
        onCerrar={() => setAction(null)}
        onConfirmar={() =>
          action?.tipo === 'disable' &&
          void cambiar(action.user, { disabled: 'true' }, {
            type: 'success',
            title: 'User Disabled!',
            text: `User [${action.user.username}] account was disabled successfully.`,
          })
        }
      />

      <Confirmar
        abierto={action?.tipo === '2fa'}
        titulo="Disable 2FA"
        text={`Are you sure you want to disable Two-factor authentication (2FA) for user [${action?.user.username ?? ''}] ?`}
        etiqueta="Disable"
        onCerrar={() => setAction(null)}
        onConfirmar={() =>
          action?.tipo === '2fa' &&
          void cambiar(action.user, { totpEnabled: 'false' }, {
            type: 'success',
            title: '2FA Disabled!',
            text: `Two-factor authentication was disabled successfully for user [${action.user.username}].`,
          })
        }
      />

      <Confirmar
        abierto={action?.tipo === 'delete'}
        titulo="Delete User"
        text={`Are you sure you want to delete the user [${action?.user.username ?? ''}] account?`}
        etiqueta="Delete"
        onCerrar={() => setAction(null)}
        onConfirmar={() => action?.tipo === 'delete' && void borrar(action.user)}
      />

      <AnadirUsuario
        abierto={anadir}
        token={token}
        onCerrar={() => setAnadir(false)}
        onAnadido={(u) => {
          setUsuarios((list) => [u, ...list])
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

/* `addUser` (auth.js:1178). The order of the four validations is contract. */
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
  const [user, setUsuario] = useState('')
  const [pass, setPass] = useState('')
  const [confirmar, setConfirmar] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setDisplayName('')
    setUsuario('')
    setPass('')
    setConfirmar('')
  }, [abierto])

  async function anadir() {
    if (user === '') {
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

    setBusy(true)
    const outcome = await createUser(token, displayName, user, pass)
    setBusy(false)

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
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void anadir()}>
            Add
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
            value={user}
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
`showResetUserPasswordModal` / `resetUserPassword` (auth.js:1546-1627). Upstream
REUSES the "Change Password" modal by changing its title to "Reset Password",
hiding the current password and the OTP, and renaming the button to "Reset". The
success alert comes out on the PAGE, because the modal has already closed.
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
  const [busy, setBusy] = useState(false)

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

    setBusy(true)
    const outcome = await resetUserPassword(token, username, nueva)
    setBusy(false)

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
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void guardar()}>
            Reset
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
