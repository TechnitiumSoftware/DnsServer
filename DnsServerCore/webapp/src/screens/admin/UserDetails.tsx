import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select, Textarea } from '../../ui/Field'
import { CeldaAgente, CeldaUltimaVez } from '../../ui/Sesion'
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
import { Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import { Avisador } from '../../ui/Avisador'
import { Menu } from '../../ui/Menu'

/*
`showUserDetailsModal` / `saveUserDetails` / `deleteUserSession`
(auth.js:1244-1481). It is Administration's most loaded modal and TWO places open
it: the Users tab (with a row to update) and the Sessions tab (without one).
Upstream tells the two cases apart by whether the link carried a `data-id`, and
in the second it refreshes the sessions list on save instead of redrawing the row.

Two interface rules that come from the user themselves and not from permissions:

  · An SSO user has the name and the display name locked, because the provider
    governs them (WebServiceAuthApi.cs:1085 and 1093 reject them).
  · Their group membership is locked ONLY if `ssoManagedGroups` is also on (line
    1119). They are two different conditions and cannot be merged.

And an important consequence: the locked fields are NOT sent. Upstream composes
the query by looking at each field's `disabled`, so an SSO user saves only
`disabled` and `sessionTimeoutSeconds`.
*/

interface Props {
  abierto: boolean
  username: string | null
  token: string | null
  cluster: ClusterState | null
  onCerrar: () => void
  /** The Users tab redraws its row; the Sessions tab reloads the list. */
  alGuardar: (u: AdminUserDetails) => void
  onAviso: (a: Aviso) => void
}


/* `sortTable('tbodyUserDetailsActiveSessions', 0..3)`. */
const CLAVES: Claves<AdminSession> = {
  session: (s) =>
    [s.tokenName ?? '', `[${s.partialToken}]`, s.isCurrentSession ? '(current)' : '', s.type]
      .filter(Boolean)
      .join(' '),
  lastSeen: (s) => s.lastSeen,
  address: (s) => s.lastSeenRemoteAddress,
  agent: (s) => s.lastSeenUserAgent,
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
  const { filas: sesionesVisibles, orden, alternar } = useOrden(CLAVES, sesiones)
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

    // "if (sessionTimeoutSeconds === "") sessionTimeoutSeconds = 1800" — it is
    // the modal's only field with a default value (auth.js:1424).
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
    // auth.js:1382 — here the `node` travels ONLY if the session is an API token.
    // The Sessions tab always sends it; this modal does not.
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
        tamano="ancho"
        title="User Details"
        acciones={
          <>
            <Button variant="primary" disabled={ocupado || cargando} onClick={() => void guardar()}>
              Save
            </Button>
          </>
        }
      >
        <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

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
                conmutador
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
                <Textarea
                  mono
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
                <Select
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
                </Select>
              )}
            </MRow>

            <p className={styles.sub}>Active Sessions</p>
            <Tabla
              cabecera={
                <>
                  <Th campo="session" orden={orden} onOrdenar={alternar}>Session</Th>
                  <Th campo="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                  <Th campo="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
                  <Th campo="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
                  <th className={tbl.celdaAcciones} />
                </>
              }
            >
              {sesionesVisibles.map((s) => (
                <tr key={s.partialToken}>
                  <td>
                    <CeldaSesion sesion={s} />
                  </td>
                  <td className={styles.nowrap}>
                    <CeldaUltimaVez fecha={fechaHora(s.lastSeen)} hace={desdeAhora(s.lastSeen)} />
                  </td>
                  <td className={styles.mono}>{s.lastSeenRemoteAddress}</td>
                  <td>
                    <CeldaAgente>{s.lastSeenUserAgent}</CeldaAgente>
                  </td>
                  <td className={tbl.celdaAcciones}>
                    <div className={tbl.acciones}>
                      {/* Inside the menu, as in "Administration > Sessions" and as
                          in upstream, which also puts it in a dropdown
                          (`auth.js`, `deleteUserSession`). Loose it was the only
                          row "Delete" without the friction the rule demands, in a
                          console with no undo. */}
                      <Menu etiqueta={`Actions for ${s.partialToken}`}>
                        {(cerrar) => (
                          <button
                            type="button"
                            data-variant="danger"
                            onClick={() => { cerrar(); setPorBorrar(s) }}
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
