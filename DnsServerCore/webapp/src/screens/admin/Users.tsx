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
import { AccionFila, Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import { Menu, Separador } from '../../ui/Menu'
import { nuncaUsado } from '../../api/zones'
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

type Accion =
  | { tipo: 'disable'; user: AdminUser }
  | { tipo: '2fa'; user: AdminUser }
  | { tipo: 'delete'; user: AdminUser }

/** The date of a login, or "Never" if it is .NET's sentinel. */
function acceso(iso: string, direccion: string): string {
  return nuncaUsado(iso) ? 'Never' : `${fechaHora(iso)} from ${direccion}`
}

/* `sortTable('tbodyAdminUsers', 0..6)`. */
const CLAVES: Claves<AdminUser> = {
  username: (u) => u.username,
  display: (u) => u.displayName,
  type: (u) => (u.isSsoUser ? 'Remote/SSO' : 'Local'),
  totp: (u) => (u.isSsoUser ? 'SSO Managed' : u.totpEnabled ? 'Enabled' : 'Disabled'),
  status: (u) => (u.disabled ? 'Disabled' : 'Enabled'),
  recent: (u) => acceso(u.recentSessionLoggedOn, u.recentSessionRemoteAddress),
  previous: (u) => acceso(u.previousSessionLoggedOn, u.previousSessionRemoteAddress),
}

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

  const { filas: usuariosVisibles, orden, alternar } = useOrden(CLAVES, usuarios)

  function reemplazar(u: AdminUser) {
    setUsuarios((lista) => lista.map((x) => (x.username === u.username ? u : x)))
  }

  /** Changing the username from the modal leaves the row with no match by
   *  `username`; upstream replaces it by position. Here it is done by the index
   *  of the user that was opened, which is the same thing. */
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
        <Loading />
      ) : (
        <>
          <Tabla
            cabecera={
              <>
                <Th campo="username" orden={orden} onOrdenar={alternar}>Username</Th>
                <Th campo="display" orden={orden} onOrdenar={alternar}>Display Name</Th>
                <Th campo="type" orden={orden} onOrdenar={alternar}>Type</Th>
                <Th campo="totp" orden={orden} onOrdenar={alternar}>2FA Status</Th>
                <Th campo="status" orden={orden} onOrdenar={alternar}>Status</Th>
                <Th campo="recent" orden={orden} onOrdenar={alternar}>Recent Login</Th>
                <Th campo="previous" orden={orden} onOrdenar={alternar}>Previous Login</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            vacia={usuariosVisibles.length === 0}
            vacio="No User Found"
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
                  <div className={tbl.acciones}>
                    <AccionFila
                      icono="ficha"
                      nombre="View Details"
                      onClick={() => setDetalle(u.username)}
                    />
                    <AccionFila
                      icono="energia"
                      nombre={u.disabled ? 'Enable User' : 'Disable User'}
                      onClick={() =>
                        u.disabled
                          ? void cambiar(u, { disabled: 'false' }, {
                              type: 'success',
                              title: 'User Enabled!',
                              text: `User [${u.username}] account was enabled successfully.`,
                            })
                          : setAccion({ tipo: 'disable', user: u })
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
                            <button type="button" onClick={() => { cerrar(); setAccion({ tipo: '2fa', user: u }) }}>
                              Disable 2FA
                            </button>
                          )}
                          <Separador />
                          <button type="button" data-variant="danger" onClick={() => { cerrar(); setAccion({ tipo: 'delete', user: u }) }}>
                            Delete User
                          </button>
                        </>
                      )}
                    </Menu>
                  </div>
                </td>
              </tr>
            ))}
          </Tabla>
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
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void anadir()}>
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
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void guardar()}>
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
