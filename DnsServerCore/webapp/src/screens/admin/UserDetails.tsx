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
import { addToList, OPCION_BLANK, OPCION_NONE } from './tabla'
import { fechaHora, desdeAhora } from './fechas'
import {
  noticeFromFailure,
  CeldaSesion,
  Check,
  Confirm,
  MRow,
  MValue,
  adminStyles as styles,
  type Notice,
} from './partes'
import tbl from '../../ui/Table.module.css'
import frm from '../../ui/Form.module.css'
import { Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Notifier } from '../../ui/Avisador'
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
  open: boolean
  username: string | null
  token: string | null
  cluster: ClusterState | null
  onCerrar: () => void
  /** The Users tab redraws its row; the Sessions tab reloads the list. */
  alGuardar: (u: AdminUserDetails) => void
  onAviso: (a: Notice) => void
}


/* `sortTable('tbodyUserDetailsActiveSessions', 0..3)`. */
const KEYS: Keys<AdminSession> = {
  session: (s) =>
    [s.tokenName ?? '', `[${s.partialToken}]`, s.isCurrentSession ? '(current)' : '', s.type]
      .filter(Boolean)
      .join(' '),
  lastSeen: (s) => s.lastSeen,
  address: (s) => s.lastSeenRemoteAddress,
  agent: (s) => s.lastSeenUserAgent,
}

export function UserDetails({ open, username, token, cluster, onCerrar, alGuardar, onAviso }: Props) {
  const [detalle, setDetalle] = useState<AdminUserDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [notice, setAviso] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  const [displayName, setDisplayName] = useState('')
  const [newUser, setNuevoUsuario] = useState('')
  const [disabled, setDisabled] = useState(false)
  const [timeout, setTimeoutSeconds] = useState('')
  const [memberOf, setMemberOf] = useState('')
  const [sessions, setSesiones] = useState<AdminSession[]>([])
  const { rows: sesionesVisibles, sort, alternar } = useOrden(KEYS, sessions)
  const [porBorrar, setPorBorrar] = useState<AdminSession | null>(null)
  const [addGroup, setAddGroup] = useState(OPCION_BLANK)

  const load = useCallback(async () => {
    if (username == null) return
    setLoading(true)
    setAviso(null)
    const outcome = await getUser(token, username)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    const d = outcome.data.response
    setDetalle(d)
    setDisplayName(d.displayName)
    setNuevoUsuario(d.username)
    setDisabled(d.disabled)
    setTimeoutSeconds(String(d.sessionTimeoutSeconds))
    setMemberOf(d.memberOfGroups.map((g) => `${g}\n`).join(''))
    setSesiones(d.sessions)
    setAddGroup(OPCION_BLANK)
  }, [token, username])

  useEffect(() => {
    if (open) void load()
  }, [open, load])

  const perfilBloqueado = detalle?.isSsoUser === true
  const gruposBloqueados = detalle?.isSsoUser === true && detalle.ssoManagedGroups === true

  async function save() {
    if (detalle == null || username == null) return

    // "if (sessionTimeoutSeconds === "") sessionTimeoutSeconds = 1800" — it is
    // the modal's only field with a default value (auth.js:1424).
    const segundos = timeout === '' ? '1800' : timeout

    const body: Record<string, string> = {
      user: username,
      disabled: String(disabled),
      sessionTimeoutSeconds: segundos,
    }
    if (!perfilBloqueado) {
      body.displayName = displayName
      if (newUser !== username) body.newUser = newUser
    }
    if (!gruposBloqueados) body.memberOfGroups = limpiarLista(memberOf)

    setBusy(true)
    const outcome = await setUser(token, body)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    alGuardar(outcome.data.response)
    onCerrar()
    onAviso({ type: 'success', title: 'User Saved!', text: 'User details were saved successfully.' })
  }

  async function deleteSession(s: AdminSession) {
    setPorBorrar(null)
    // auth.js:1382 — here the `node` travels ONLY if the session is an API token.
    // The Sessions tab always sends it; this modal does not.
    const node = s.type === 'ApiToken' ? primaryNodeName(cluster) : undefined
    const outcome = await deleteAdminSession(token, s.partialToken, node)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    setSesiones((list) => list.filter((x) => x.partialToken !== s.partialToken))
    setAviso({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
  }

  return (
    <>
      <Dialog
        open={open}
        onOpenChange={(o) => !o && onCerrar()}
        size="wide"
        title="User Details"
        actions={
          <>
            <Button variant="primary" disabled={busy || loading} onClick={() => void save()}>
              Save
            </Button>
          </>
        }
      >
        <Notifier notice={notice} onCerrar={() => setAviso(null)} />

        {loading || detalle == null ? (
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
                  value={newUser}
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
                toggle
                label="Disable User Account"
                checked={disabled}
                onChange={setDisabled}
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
                    setMemberOf((t) => addToList(t, e.target.value))
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
            <Table
              header={
                <>
                  <Th field="session" sort={sort} onOrdenar={alternar}>Session</Th>
                  <Th field="lastSeen" sort={sort} onOrdenar={alternar}>Last Seen</Th>
                  <Th field="address" sort={sort} onOrdenar={alternar}>Remote Address</Th>
                  <Th field="agent" sort={sort} onOrdenar={alternar}>User Agent</Th>
                  <th className={tbl.celdaAcciones} />
                </>
              }
            >
              {sesionesVisibles.map((s) => (
                <tr key={s.partialToken}>
                  <td>
                    <CeldaSesion session={s} />
                  </td>
                  <td className={styles.nowrap}>
                    <CeldaUltimaVez date={fechaHora(s.lastSeen)} hace={desdeAhora(s.lastSeen)} />
                  </td>
                  <td className={styles.mono}>{s.lastSeenRemoteAddress}</td>
                  <td>
                    <CeldaAgente>{s.lastSeenUserAgent}</CeldaAgente>
                  </td>
                  <td className={tbl.celdaAcciones}>
                    <div className={tbl.actions}>
                      {/* Inside the menu, as in "Administration > Sessions" and as
                          in upstream, which also puts it in a dropdown
                          (`auth.js`, `deleteUserSession`). Loose it was the only
                          row "Delete" without the friction the rule demands, in a
                          console with no undo. */}
                      <Menu etiqueta={`Actions for ${s.partialToken}`}>
                        {(close) => (
                          <button
                            type="button"
                            data-variant="danger"
                            onClick={() => { close(); setPorBorrar(s) }}
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
            <div className={styles.count}>
              <span>{`Total Sessions: ${sessions.length}`}</span>
            </div>
          </>
        )}
      </Dialog>

      <Confirm
        open={porBorrar !== null}
        titulo="Delete Session"
        text={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void deleteSession(porBorrar)}
      />
    </>
  )
}
