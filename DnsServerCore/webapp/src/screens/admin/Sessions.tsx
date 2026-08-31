import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select } from '../../ui/Field'
import { CeldaAgente, CeldaUltimaVez } from '../../ui/Sesion'
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
import { desdeAhora, fechaHora } from './fechas'
import {
  avisoDeFallo,
  CeldaSesion,
  Confirmar,
  MRow,
  SelectorNodo,
  adminStyles as styles,
  type Aviso,
} from './partes'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { Avisador } from '../../ui/Avisador'

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
  onAviso: (a: Aviso) => void
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

export function Sessions({ token, cluster, onAviso }: Props) {
  const [node, setNodo] = useState('')
  const [sessions, setSesiones] = useState<AdminSession[]>([])
  const [servidor, setServidor] = useState('')
  const [loading, setLoading] = useState(true)
  const [porBorrar, setPorBorrar] = useState<AdminSession | null>(null)
  const [crear, setCrear] = useState(false)
  const [verUsuario, setVerUsuario] = useState<string | null>(null)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await listSessions(token, node)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setSesiones([])
      onAviso(avisoDeFallo(outcome))
      return
    }
    setSesiones(outcome.data.response.sessions)
    setServidor(outcome.data.server)
  }, [token, node, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  const { rows: sesionesVisibles, orden, alternar } = useOrden(KEYS, sessions)

  const primario = primaryNodeName(cluster)
  const puedeCrearToken = primario === '' || primario === servidor

  async function borrar(s: AdminSession) {
    setPorBorrar(null)
    const target = s.type === 'ApiToken' ? primario : node
    const outcome = await deleteAdminSession(token, s.partialToken, target)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setSesiones((list) => list.filter((x) => x.partialToken !== s.partialToken))
    onAviso({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        titulo="Sessions"
        actions={<>{puedeCrearToken && (
            <Button variant="primary" onClick={() => setCrear(true)}>
              Create Token
            </Button>
          )}
          <SelectorNodo cluster={cluster} value={node} onChange={setNodo} label="Cluster Node" /></>}
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          <Table
            header={
              <>
                <Th field="username" orden={orden} onOrdenar={alternar}>Username</Th>
                <Th field="session" orden={orden} onOrdenar={alternar}>Session</Th>
                <Th field="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                <Th field="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
                <Th field="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            isEmpty={sesionesVisibles.length === 0}
            emptyText="No Session Found"
            columnas={6}
          >
            {sesionesVisibles.map((s) => (
              <tr key={s.partialToken}>
                <td>
                  <button
                    type="button"
                    className={styles.link}
                    onClick={() => setVerUsuario(s.username)}
                  >
                    {s.username}
                  </button>
                </td>
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
                    <AccionFila
                      icono="ficha"
                      name="View Details"
                      onClick={() => setVerUsuario(s.username)}
                    />
                    <Menu etiqueta={`Actions for ${s.partialToken}`}>
                      {(cerrar) => (
                        <button type="button" data-variant="danger" onClick={() => { cerrar(); setPorBorrar(s) }}>
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

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Session"
        text={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void borrar(porBorrar)}
      />

      <CrearApiToken
        abierto={crear}
        token={token}
        onCerrar={() => setCrear(false)}
        onCreated={() => void cargar()}
      />

      {/* It is mounted only when needed so its load starts from scratch every
          time it opens, just as in upstream. On saving from here upstream does NOT
          redraw any row: it reloads the sessions list (auth.js:1467). */}
      {verUsuario != null && (
        <UserDetails
          abierto
          username={verUsuario}
          token={token}
          cluster={cluster}
          onCerrar={() => setVerUsuario(null)}
          alGuardar={() => void cargar()}
          onAviso={onAviso}
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
  abierto,
  token,
  onCerrar,
  onCreated,
}: {
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onCreated: () => void
}) {
  const [users, setUsuarios] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [user, setUsuario] = useState('')
  const [name, setNombre] = useState('')
  const [created, setCreated] = useState<CreatedApiToken | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!abierto) return
    let vivo = true
    setLoading(true)
    setAviso(null)
    setCreated(null)
    setNombre('')
    void listUsers(token).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      const nombres = outcome.data.response.users.map((u) => u.username)
      setUsuarios(nombres)
      setUsuario(nombres[0] ?? '')
    })
    return () => {
      vivo = false
    }
  }, [abierto, token])

  async function crear() {
    if (user === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please select a username.' })
      return
    }
    if (name === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a token name.' })
      return
    }

    setBusy(true)
    const outcome = await createApiToken(token, user, name)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    setCreated(outcome.data.response)
    setAviso({
      type: 'success',
      title: 'Token Created!',
      text: 'API token was created successfully.',
    })
    onCreated()
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title="Create API Token"
      actions={
        <>
          {created == null && (
            <Button variant="primary" disabled={busy || loading} onClick={() => void crear()}>
              Create
            </Button>
          )}
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {created != null ? (
        <div className={styles.salida}>
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
                onChange={(e) => setUsuario(e.target.value)}
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
