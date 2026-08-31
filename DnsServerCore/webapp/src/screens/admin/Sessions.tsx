import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select } from '../../ui/Field'
import { AgentCell, LastSeenCell } from '../../ui/SessionCells'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import {
  createApiToken,
  deleteAdminSession,
  listSessions,
  listUsers,
  type AdminSession,
  type CreatedApiToken,
} from '../../api/admin'
import { primaryNodeName, type ClusterState } from '../../api/admin-cluster'
import { UserDetails } from './UserDetails'
import { fromNow, fechaHora } from './dates'
import {
  noticeFromFailure,
  SessionCell,
  Confirm,
  MRow,
  NodePicker,
  adminStyles as styles,
  type Notice,
} from './parts'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { Notifier } from '../../ui/Notifier'

/*
`refreshAdminSessions`, `showCreateApiTokenModal`, `createApiToken` and
`deleteAdminSession` (auth.js:856-1082).

Three things you do not see by looking at the table:

  · The "Create Token" button hides when this server is NOT the cluster's primary
    node (auth.js:915-918), because the endpoint only runs there
    (DnsWebService.cs:2298). The check is against the `server` of the response's
    envelope, not against the session's domain.
  · When deleting, the `node` that travels depends on the session's TYPE: the
    primary node if it is an API token, the node chosen in the dropdown in any
    other case (auth.js:1050-1055).
  · The delete's success alert comes out on the PAGE; the create-token modal's,
    inside the modal. Upstream picks the place on each call.
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onNotice: (a: Notice) => void
}

/* `sortTable('tbodyAdminSessions', 0..4)`. The "Session" cell is read as it is
   drawn: the token's name if it has one, the partial token and its type. */
const KEYS: Keys<AdminSession> = {
  username: (s) => s.username,
  session: (s) =>
    [s.tokenName ?? '', `[${s.partialToken}]`, s.isCurrentSession ? '(current)' : '', s.type]
      .filter(Boolean)
      .join(' '),
  lastSeen: (s) => fechaHora(s.lastSeen),
  address: (s) => s.lastSeenRemoteAddress,
  agent: (s) => s.lastSeenUserAgent,
}

export function Sessions({ token, cluster, onNotice }: Props) {
  const [node, setNode] = useState('')
  const [sessions, setSessions] = useState<AdminSession[]>([])
  const [servidor, setServidor] = useState('')
  const [loading, setLoading] = useState(true)
  const [pendingDelete, setPendingDelete] = useState<AdminSession | null>(null)
  const [create, setCrear] = useState(false)
  const [viewUser, setViewUser] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await listSessions(token, node)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setSessions([])
      onNotice(noticeFromFailure(outcome))
      return
    }
    setSessions(outcome.data.response.sessions)
    setServidor(outcome.data.server)
  }, [token, node, onNotice])

  useEffect(() => {
    void load()
  }, [load])

  const { rows: visibleSessions, sort, toggle } = useOrden(KEYS, sessions)

  const primario = primaryNodeName(cluster)
  const puedeCrearToken = primario === '' || primario === servidor

  async function remove(s: AdminSession) {
    setPendingDelete(null)
    const target = s.type === 'ApiToken' ? primario : node
    const outcome = await deleteAdminSession(token, s.partialToken, target)

    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    setSessions((list) => list.filter((x) => x.partialToken !== s.partialToken))
    onNotice({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        title="Sessions"
        actions={<>{puedeCrearToken && (
            <Button variant="primary" onClick={() => setCrear(true)}>
              Create Token
            </Button>
          )}
          <NodePicker cluster={cluster} value={node} onChange={setNode} label="Cluster Node" /></>}
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          <Table
            header={
              <>
                <Th field="username" sort={sort} onSort={toggle}>Username</Th>
                <Th field="session" sort={sort} onSort={toggle}>Session</Th>
                <Th field="lastSeen" sort={sort} onSort={toggle}>Last Seen</Th>
                <Th field="address" sort={sort} onSort={toggle}>Remote Address</Th>
                <Th field="agent" sort={sort} onSort={toggle}>User Agent</Th>
                <th className={tbl.actionsCell} />
              </>
            }
            isEmpty={visibleSessions.length === 0}
            emptyText="No Session Found"
            columns={6}
          >
            {visibleSessions.map((s) => (
              <tr key={s.partialToken}>
                <td>
                  <button
                    type="button"
                    className={styles.link}
                    onClick={() => setViewUser(s.username)}
                  >
                    {s.username}
                  </button>
                </td>
                <td>
                  <SessionCell session={s} />
                </td>
                <td className={styles.nowrap}>
                  <LastSeenCell date={fechaHora(s.lastSeen)} ago={fromNow(s.lastSeen)} />
                </td>
                <td className={styles.mono}>{s.lastSeenRemoteAddress}</td>
                <td>
                  <AgentCell>{s.lastSeenUserAgent}</AgentCell>
                </td>
                <td className={tbl.actionsCell}>
                  <div className={tbl.actions}>
                    <RowAction
                      icon="card"
                      name="View Details"
                      onClick={() => setViewUser(s.username)}
                    />
                    <Menu label={`Actions for ${s.partialToken}`}>
                      {(close) => (
                        <button type="button" data-variant="danger" onClick={() => { close(); setPendingDelete(s) }}>
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

      <Confirm
        open={pendingDelete !== null}
        title="Delete Session"
        text={`Are you sure you want to delete the session [${pendingDelete?.partialToken ?? ''}] ?`}
        label="Delete"
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && void remove(pendingDelete)}
      />

      <CrearApiToken
        open={create}
        token={token}
        onClose={() => setCrear(false)}
        onCreated={() => void load()}
      />

      {/* It is mounted only when needed so its load starts from scratch every
          time it opens, just as in upstream. On saving from here upstream does NOT
          redraw any row: it reloads the sessions list (auth.js:1467). */}
      {viewUser != null && (
        <UserDetails
          open
          username={viewUser}
          token={token}
          cluster={cluster}
          onClose={() => setViewUser(null)}
          onSaved={() => void load()}
          onNotice={onNotice}
        />
      )}
    </>
  )
}

/*
`showCreateApiTokenModal` (auth.js:936). It is the administrative sibling of the
user menu's "Create API Token" modal: here the username is CHOSEN from a dropdown
loaded with `admin/users/list`, and the endpoint is
`admin/sessions/createToken`, not `user/createToken`.
*/
function CrearApiToken({
  open,
  token,
  onClose,
  onCreated,
}: {
  open: boolean
  token: string | null
  onClose: () => void
  onCreated: () => void
}) {
  const [users, setUsers] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [user, setUser] = useState('')
  const [name, setNombre] = useState('')
  const [created, setCreated] = useState<CreatedApiToken | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    let live = true
    setLoading(true)
    setNotice(null)
    setCreated(null)
    setNombre('')
    void listUsers(token).then((outcome) => {
      if (!live) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setNotice(noticeFromFailure(outcome))
        return
      }
      const names = outcome.data.response.users.map((u) => u.username)
      setUsers(names)
      setUser(names[0] ?? '')
    })
    return () => {
      live = false
    }
  }, [open, token])

  async function create() {
    if (user === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please select a username.' })
      return
    }
    if (name === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter a token name.' })
      return
    }

    setBusy(true)
    const outcome = await createApiToken(token, user, name)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    setCreated(outcome.data.response)
    setNotice({
      type: 'success',
      title: 'Token Created!',
      text: 'API token was created successfully.',
    })
    onCreated()
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Create API Token"
      actions={
        <>
          {created == null && (
            <Button variant="primary" disabled={busy || loading} onClick={() => void create()}>
              Create
            </Button>
          )}
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      {created != null ? (
        <div className={styles.output}>
          <MRow label="Username">{(id) => <Input id={id} value={created.username} readOnly />}</MRow>
          <MRow label="Token Name">
            {(id) => <Input id={id} value={created.tokenName} readOnly />}
          </MRow>
          <MRow label="Token">{(id) => <Input id={id} mono value={created.token} readOnly />}</MRow>
        </div>
      ) : loading ? (
        <Loading />
      ) : (
        <>
          <MRow label="Username">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={user}
                onChange={(e) => setUser(e.target.value)}
              >
                {users.map((u) => (
                  <option key={u} value={u}>
                    {u}
                  </option>
                ))}
              </Select>
            )}
          </MRow>
          <MRow label="Token Name">
            {(id) => (
              <Input
                id={id}
                value={name}
                maxLength={255}
                onChange={(e) => setNombre(e.target.value)}
              />
            )}
          </MRow>
        </>
      )}
    </Dialog>
  )
}
