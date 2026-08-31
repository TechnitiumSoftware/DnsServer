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
import { AccionFila, Th, useOrden, type Claves, Tabla } from '../../ui/Table'
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
const CLAVES: Claves<AdminSession> = {
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
  const [nodo, setNodo] = useState('')
  const [sesiones, setSesiones] = useState<AdminSession[]>([])
  const [servidor, setServidor] = useState('')
  const [cargando, setCargando] = useState(true)
  const [porBorrar, setPorBorrar] = useState<AdminSession | null>(null)
  const [crear, setCrear] = useState(false)
  const [verUsuario, setVerUsuario] = useState<string | null>(null)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await listSessions(token, nodo)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setSesiones([])
      onAviso(avisoDeFallo(outcome))
      return
    }
    setSesiones(outcome.data.response.sessions)
    setServidor(outcome.data.server)
  }, [token, nodo, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  const { filas: sesionesVisibles, orden, alternar } = useOrden(CLAVES, sesiones)

  const primario = primaryNodeName(cluster)
  const puedeCrearToken = primario === '' || primario === servidor

  async function borrar(s: AdminSession) {
    setPorBorrar(null)
    const node = s.type === 'ApiToken' ? primario : nodo
    const outcome = await deleteAdminSession(token, s.partialToken, node)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setSesiones((lista) => lista.filter((x) => x.partialToken !== s.partialToken))
    onAviso({
      type: 'success',
      title: 'Session Deleted!',
      text: 'The user session was deleted successfully.',
    })
  }

  return (
    <>
      <SectionHeader
        seccion="Administration"
        titulo="Sessions"
        acciones={<>{puedeCrearToken && (
            <Button variant="primary" onClick={() => setCrear(true)}>
              Create Token
            </Button>
          )}
          <SelectorNodo cluster={cluster} value={nodo} onChange={setNodo} label="Cluster Node" /></>}
      />

      {cargando ? (
        <Loading />
      ) : (
        <>
          <Tabla
            cabecera={
              <>
                <Th campo="username" orden={orden} onOrdenar={alternar}>Username</Th>
                <Th campo="session" orden={orden} onOrdenar={alternar}>Session</Th>
                <Th campo="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                <Th campo="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
                <Th campo="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            vacia={sesionesVisibles.length === 0}
            vacio="No Session Found"
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
                    <AccionFila
                      icono="ficha"
                      nombre="View Details"
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
          </Tabla>
          <div className={styles.count}>
            <span>{`Total Sessions: ${sesiones.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Session"
        texto={`Are you sure you want to delete the session [${porBorrar?.partialToken ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void borrar(porBorrar)}
      />

      <CrearApiToken
        abierto={crear}
        token={token}
        onCerrar={() => setCrear(false)}
        onCreado={() => void cargar()}
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
  onCreado,
}: {
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onCreado: () => void
}) {
  const [usuarios, setUsuarios] = useState<string[]>([])
  const [cargando, setCargando] = useState(true)
  const [usuario, setUsuario] = useState('')
  const [nombre, setNombre] = useState('')
  const [creado, setCreado] = useState<CreatedApiToken | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    let vivo = true
    setCargando(true)
    setAviso(null)
    setCreado(null)
    setNombre('')
    void listUsers(token).then((outcome) => {
      if (!vivo) return
      setCargando(false)
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
    if (usuario === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please select a username.' })
      return
    }
    if (nombre === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a token name.' })
      return
    }

    setOcupado(true)
    const outcome = await createApiToken(token, usuario, nombre)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    setCreado(outcome.data.response)
    setAviso({
      type: 'success',
      title: 'Token Created!',
      text: 'API token was created successfully.',
    })
    onCreado()
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title="Create API Token"
      acciones={
        <>
          {creado == null && (
            <Button variant="primary" disabled={ocupado || cargando} onClick={() => void crear()}>
              Create
            </Button>
          )}
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {creado != null ? (
        <div className={styles.salida}>
          <MRow label="Username">{(id) => <Input id={id} value={creado.username} readOnly />}</MRow>
          <MRow label="Token Name">
            {(id) => <Input id={id} value={creado.tokenName} readOnly />}
          </MRow>
          <MRow label="Token">{(id) => <Input id={id} mono value={creado.token} readOnly />}</MRow>
        </div>
      ) : cargando ? (
        <Loading />
      ) : (
        <>
          <MRow label="Username">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={usuario}
                onChange={(e) => setUsuario(e.target.value)}
              >
                {usuarios.map((u) => (
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
                value={nombre}
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
