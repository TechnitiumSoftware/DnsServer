import { useCallback, useEffect, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input } from '../../ui/Field'
import { Loading } from '../../ui/Empty'
import {
  deleteAdminSession,
  getUser,
  setUser,
  type AdminSession,
  type AdminUserDetails,
} from '../../api/admin'
import { primaryNodeName, type ClusterState } from '../../api/admin-cluster'
import { limpiarLista } from '../settings/model'
import { anadirALaLista, OPCION_BLANK, OPCION_NONE } from './tabla'
import { fechaHora, desdeAhora } from './fechas'
import {
  avisoDeFallo,
  CeldaSesion,
  Check,
  Confirmar,
  MRow,
  MValue,
  adminStyles as styles,
  type Aviso,
} from './partes'
import tbl from '../../ui/Table.module.css'
import frm from '../../ui/Form.module.css'

/*
`showUserDetailsModal` / `saveUserDetails` / `deleteUserSession`
(auth.js:1244-1481). Es el modal más cargado de Administration y lo abren DOS
sitios: la pestaña Users (con fila que actualizar) y la pestaña Sessions (sin
ella). Upstream distingue los dos casos por si el enlace traía `data-id`, y en
el segundo refresca la lista de sesiones al guardar en vez de repintar la fila.

Dos reglas de la interfaz que salen del propio usuario y no de los permisos:

  · Un usuario de SSO tiene el nombre y el nombre visible bloqueados, porque los
    gobierna el proveedor (WebServiceAuthApi.cs:1085 y 1093 lo rechazan).
  · Su pertenencia a grupos se bloquea SÓLO si además `ssoManagedGroups` está
    activo (línea 1119). Son dos condiciones distintas y no se pueden unificar.

Y una consecuencia importante: los campos bloqueados NO se envían. Upstream
compone la query mirando el `disabled` de cada campo, así que un usuario de SSO
guarda únicamente `disabled` y `sessionTimeoutSeconds`.
*/

interface Props {
  abierto: boolean
  username: string | null
  token: string | null
  cluster: ClusterState | null
  onCerrar: () => void
  /** La pestaña Users repinta su fila; la pestaña Sessions recarga la lista. */
  alGuardar: (u: AdminUserDetails) => void
  onAviso: (a: Aviso) => void
}

export function UserDetails({ abierto, username, token, cluster, onCerrar, alGuardar, onAviso }: Props) {
  const [detalle, setDetalle] = useState<AdminUserDetails | null>(null)
  const [cargando, setCargando] = useState(true)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  const [displayName, setDisplayName] = useState('')
  const [nuevoUsuario, setNuevoUsuario] = useState('')
  const [deshabilitado, setDeshabilitado] = useState(false)
  const [timeout, setTimeoutSeconds] = useState('')
  const [memberOf, setMemberOf] = useState('')
  const [sesiones, setSesiones] = useState<AdminSession[]>([])
  const [porBorrar, setPorBorrar] = useState<AdminSession | null>(null)
  const [addGroup, setAddGroup] = useState(OPCION_BLANK)

  const cargar = useCallback(async () => {
    if (username == null) return
    setCargando(true)
    setAviso(null)
    const outcome = await getUser(token, username)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    const d = outcome.data.response
    setDetalle(d)
    setDisplayName(d.displayName)
    setNuevoUsuario(d.username)
    setDeshabilitado(d.disabled)
    setTimeoutSeconds(String(d.sessionTimeoutSeconds))
    setMemberOf(d.memberOfGroups.map((g) => `${g}\n`).join(''))
    setSesiones(d.sessions)
    setAddGroup(OPCION_BLANK)
  }, [token, username])

  useEffect(() => {
    if (abierto) void cargar()
  }, [abierto, cargar])

  const perfilBloqueado = detalle?.isSsoUser === true
  const gruposBloqueados = detalle?.isSsoUser === true && detalle.ssoManagedGroups === true

  async function guardar() {
    if (detalle == null || username == null) return

    // «if (sessionTimeoutSeconds === "") sessionTimeoutSeconds = 1800» — es el
    // único campo del modal con valor por defecto (auth.js:1424).
    const segundos = timeout === '' ? '1800' : timeout

    const body: Record<string, string> = {
      user: username,
      disabled: String(deshabilitado),
      sessionTimeoutSeconds: segundos,
    }
    if (!perfilBloqueado) {
      body.displayName = displayName
      if (nuevoUsuario !== username) body.newUser = nuevoUsuario
    }
    if (!gruposBloqueados) body.memberOfGroups = limpiarLista(memberOf)

    setOcupado(true)
    const outcome = await setUser(token, body)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    alGuardar(outcome.data.response)
    onCerrar()
    onAviso({ type: 'success', title: 'User Saved!', text: 'User details were saved successfully.' })
  }

  async function borrarSesion(s: AdminSession) {
    setPorBorrar(null)
    // auth.js:1382 — aquí el `node` viaja SÓLO si la sesión es un token de API.
    // La pestaña Sessions lo manda siempre; este modal no.
    const node = s.type === 'ApiToken' ? primaryNodeName(cluster) : undefined
    const outcome = await deleteAdminSession(token, s.partialToken, node)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    setSesiones((lista) => lista.filter((x) => x.partialToken !== s.partialToken))
    setAviso({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
  }

  return (
    <>
      <Dialog
        open={abierto}
        onOpenChange={(o) => !o && onCerrar()}
        title="User Details"
        acciones={
          <>
            <Button variant="primary" disabled={ocupado || cargando} onClick={() => void guardar()}>
              Save
            </Button>
          </>
        }
      >
        {aviso && (
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        )}

        {cargando || detalle == null ? (
          <Loading />
        ) : (
          <>
            <MRow label="Display Name">
              {(id) => (
                <Input
                  id={id}
                  value={displayName}
                  placeholder="display name"
                  maxLength={255}
                  disabled={perfilBloqueado}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              )}
            </MRow>

            <MRow label="Username">
              {(id) => (
                <Input
                  id={id}
                  value={nuevoUsuario}
                  placeholder="username"
                  maxLength={255}
                  disabled={perfilBloqueado}
                  onChange={(e) => setNuevoUsuario(e.target.value)}
                />
              )}
            </MRow>

            <MValue label="Type" value={detalle.isSsoUser ? 'Remote/SSO' : 'Local'} />
            <MValue
              label="2FA Status"
              value={detalle.isSsoUser ? 'SSO Managed' : detalle.totpEnabled ? 'Enabled' : 'Disabled'}
            />

            <div className={frm.mrow}>
              <div />
              <Check
                label="Disable User Account"
                checked={deshabilitado}
                onChange={setDeshabilitado}
              />
            </div>

            <MRow label="Session Timeout">
              {(id) => (
                <div className={styles.ctlLine}>
                  <Input
                    id={id}
                    type="number"
                    placeholder="1800"
                    style={{ width: 100 }}
                    value={timeout}
                    onChange={(e) => setTimeoutSeconds(e.target.value)}
                  />
                  <span className={styles.suffix}>
                    seconds (valid range 0-604800; default 1800; set 0 to disable)
                  </span>
                </div>
              )}
            </MRow>

            <MRow label="Member Of">
              {(id) => (
                <textarea
                  id={id}
                  rows={5}
                  className={styles.area}
                  disabled={gruposBloqueados}
                  value={memberOf}
                  onChange={(e) => setMemberOf(e.target.value)}
                />
              )}
            </MRow>

            <MRow label="Add Group">
              {(id) => (
                <select
                  id={id}
                  className={styles.select}
                  disabled={gruposBloqueados}
                  value={addGroup}
                  onChange={(e) => {
                    setAddGroup(e.target.value)
                    setMemberOf((t) => anadirALaLista(t, e.target.value))
                  }}
                >
                  <option value={OPCION_BLANK} />
                  <option value={OPCION_NONE}>None</option>
                  {(detalle.groups ?? []).map((g) => (
                    <option key={g} value={g}>
                      {g}
                    </option>
                  ))}
                </select>
              )}
            </MRow>

            <p className={styles.sub}>Active Sessions</p>
            <div className={tbl.wrap}>
              <table className={tbl.tabla}>
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Last Seen</th>
                    <th>Remote Address</th>
                    <th>User Agent</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {sesiones.map((s) => (
                    <tr key={s.partialToken}>
                      <td>
                        <CeldaSesion sesion={s} />
                      </td>
                      <td className={styles.nowrap}>
                        <div className={styles.mono}>{fechaHora(s.lastSeen)}</div>
                        <div className={styles.meta}>{`(${desdeAhora(s.lastSeen)})`}</div>
                      </td>
                      <td className={styles.mono}>{s.lastSeenRemoteAddress}</td>
                      <td>
                        <span className={styles.ua}>{s.lastSeenUserAgent}</span>
                      </td>
                      <td>
                        <div className={styles.rowacts}>
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => setPorBorrar(s)}
                          >
                            Delete Session
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className={styles.count}>
              <span>{`Total Sessions: ${sesiones.length}`}</span>
            </div>
          </>
        )}
      </Dialog>

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Session"
        texto={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void borrarSesion(porBorrar)}
      />
    </>
  )
}
