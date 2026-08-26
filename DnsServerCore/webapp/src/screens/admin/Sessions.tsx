import { useCallback, useEffect, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select } from '../../ui/Field'
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
import { AccionFila, Th, useOrden, type Claves } from '../../ui/Table'
import { Menu } from '../../ui/Menu'

/*
`refreshAdminSessions`, `showCreateApiTokenModal`, `createApiToken` y
`deleteAdminSession` (auth.js:856-1082).

Tres cosas que no se ven mirando la tabla:

  · El botón «Create Token» se esconde cuando este servidor NO es el nodo
    primario del cluster (auth.js:915-918), porque el endpoint sólo corre allí
    (DnsWebService.cs:2298). La comprobación es contra el `server` de la
    envoltura de la respuesta, no contra el dominio de la sesión.
  · Al borrar, el `node` que viaja depende del TIPO de sesión: el nodo primario
    si es un token de API, el nodo elegido en el desplegable en cualquier otro
    caso (auth.js:1050-1055).
  · El aviso de éxito del borrado sale en la PÁGINA; el del modal de crear
    token, dentro del modal. Upstream elige el sitio en cada llamada.
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onAviso: (a: Aviso) => void
}

/* `sortTable('tbodyAdminSessions', 0..4)`. La celda «Session» se lee como se
   pinta: nombre del token si lo tiene, el token parcial y su tipo. */
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
          <div className={tbl.wrap}>
            <table className={tbl.tabla}>
              <thead>
                <tr>
                  <Th campo="username" orden={orden} onOrdenar={alternar}>Username</Th>
                  <Th campo="session" orden={orden} onOrdenar={alternar}>Session</Th>
                  <Th campo="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                  <Th campo="address" orden={orden} onOrdenar={alternar}>Remote Address</Th>
                  <Th campo="agent" orden={orden} onOrdenar={alternar}>User Agent</Th>
                  <th />
                </tr>
              </thead>
              <tbody>
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
                      <div className={styles.mono}>{fechaHora(s.lastSeen)}</div>
                      <div className={styles.meta}>{`(${desdeAhora(s.lastSeen)})`}</div>
                    </td>
                    <td className={styles.mono}>{s.lastSeenRemoteAddress}</td>
                    <td>
                      <span className={styles.ua}>{s.lastSeenUserAgent}</span>
                    </td>
                    <td>
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
              </tbody>
            </table>
          </div>
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

      {/* Se monta sólo cuando hace falta para que su carga arranque de cero cada
          vez que se abre, igual que en upstream. Al guardar desde aquí upstream
          NO repinta ninguna fila: recarga la lista de sesiones (auth.js:1467). */}
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
`showCreateApiTokenModal` (auth.js:936). Es el hermano administrativo del modal
«Create API Token» del menú de usuario: aquí el nombre de usuario se ELIGE de un
desplegable cargado con `admin/users/list`, y el endpoint es
`admin/sessions/createToken`, no `user/createToken`.
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
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

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
