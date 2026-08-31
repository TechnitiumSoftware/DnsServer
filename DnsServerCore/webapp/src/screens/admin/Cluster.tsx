import { useCallback, useEffect, useId, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select, Textarea } from '../../ui/Field'
import { Radios } from '../../ui/Ajustes'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty, Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import {
  deleteCluster,
  deleteSecondaryNode,
  getClusterState,
  initCluster,
  initJoinCluster,
  leaveCluster,
  promoteToPrimary,
  removeSecondaryNode,
  resyncCluster,
  setClusterOptions,
  updateIpAddress,
  updatePrimaryNode,
  type ClusterNode,
  type ClusterState,
} from '../../api/admin-cluster'
import { limpiarLista } from '../settings/model'
import { desdeAhora, fechaMinuto } from './fechas'
import {
  avisoDeFallo,
  Check,
  Confirmar,
  MRow,
  SelectorNodo,
  adminStyles as styles,
  type Aviso,
} from './partes'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import { Menu, Separador } from '../../ui/Menu'
import { GroupRow } from '../../ui/Form'

/*
La sub-pestaña Cluster (`cluster.js` entera, 1.055 líneas). Doce endpoints y
ocho modales.

Lo que hay que tener delante:

  · **El estado del cluster manda sobre la barra de acciones.** Sin cluster sólo
    se ofrece inicializar; con cluster, el nodo PROPIO decide: si es primario se
    ven «Options» y «Delete Cluster», y si es secundario «Resync», «Options» y
    «Leave Cluster» (cluster.js:248-264). No es cosmético: los endpoints que
    hay detrás sólo existen en un lado.
  · **Las acciones de cada FILA también dependen del nodo propio**, y no de la
    fila: un primario puede editarse a sí mismo y quitar secundarios; un
    secundario puede editarse a sí mismo, promocionarse, y editar la ficha del
    primario (cluster.js:207-238).
  · **«Quick Add» compara por SUBCADENA**, no por línea (cluster.js:30): con
    `10.0.0.1` ya en la lista, añadir `10.0.0.10` no hace nada. Se replica el
    comportamiento, no la intención.
  · **«Force Remove Node» cambia de endpoint**, no de parámetro:
    `primary/deleteSecondary` con la casilla puesta y `primary/removeSecondary`
    sin ella.
  · **`secondary/resync` no devuelve el estado** del cluster: se avisa y se
    remite a los Logs.

Aviso de verificación: con una sola instancia el cluster nunca llega a
inicializarse, así que la mitad de estos endpoints no se ha podido ejercitar
contra un servidor real. Están escritos contra `cluster.js` y contra
`WebServiceClusterApi.cs`, y cubiertos con pruebas de respuestas simuladas.
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onCluster: (s: ClusterState) => void
  onAviso: (a: Aviso) => void
}

type Modal =
  | { tipo: 'new' }
  | { tipo: 'join' }
  | { tipo: 'options' }
  | { tipo: 'editSelf'; nodo: ClusterNode }
  | { tipo: 'editPrimary'; nodo: ClusterNode }
  | { tipo: 'remove'; nodo: ClusterNode }
  | { tipo: 'promote'; nodo: ClusterNode }
  | { tipo: 'leave' }
  | { tipo: 'delete' }
  | { tipo: 'resync' }

/* `sortTable('tbodyAdminCluster', 0..7)`. Las tres fechas se leen por su ISO:
   la celda pinta la fecha y el «hace tanto», y las dos ordenan igual. */
const CLAVES: Claves<ClusterNode> = {
  name: (n) => n.name,
  ip: (n) => n.ipAddresses.join(' '),
  url: (n) => n.url,
  type: (n) => (n.type === 'Primary' || n.type === 'Secondary' ? n.type : 'Unknown'),
  state: (n) => n.state,
  upSince: (n) => n.upSince ?? '',
  lastSeen: (n) => (n.state !== 'Self' ? (n.lastSeen ?? '') : ''),
  synced: (n) => (n.state === 'Self' && n.type === 'Secondary' ? (n.configLastSynced ?? '') : ''),
}

export function Cluster({ token, cluster, onCluster, onAviso }: Props) {
  const [nodo, setNodo] = useState('')
  const [estado, setEstado] = useState<ClusterState | null>(cluster)
  const [cargando, setCargando] = useState(true)
  const [modal, setModal] = useState<Modal | null>(null)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await getClusterState(token, { node: nodo })
    setCargando(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setEstado(outcome.data.response)
    onCluster(outcome.data.response)
  }, [token, nodo, onCluster, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])


  function recargarCon(s: ClusterState) {
    setEstado(s)
    onCluster(s)
  }

  const nodos = estado?.clusterNodes ?? []
  const { filas: nodosVisibles, orden, alternar } = useOrden(CLAVES, nodos)
  const tipoPropio = nodos.find((n) => n.state === 'Self')?.type
  const inicializado = estado?.clusterInitialized === true
  const esPrimario = tipoPropio === 'Primary'

  async function lanzarResync() {
    setModal(null)
    const outcome = await resyncCluster(token, nodo)
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    onAviso({
      type: 'success',
      title: 'Resync Triggered!',
      text: 'A full config resync was triggered successfully. Please check the Logs for confirmation.',
    })
  }

  return (
    <>
      <SectionHeader
        seccion="Administration"
        titulo="Cluster"
        acciones={<>{inicializado && !esPrimario && (
            <Button variant="primary" onClick={() => setModal({ tipo: 'resync' })}>
              Resync
            </Button>
          )}
          {inicializado && (
            <Button variant="primary" onClick={() => setModal({ tipo: 'options' })}>
              Options
            </Button>
          )}
          {inicializado && !esPrimario && (
            <Button onClick={() => setModal({ tipo: 'leave' })}>Leave Cluster</Button>
          )}
          {inicializado && esPrimario && (
            <Button variant="danger" onClick={() => setModal({ tipo: 'delete' })}>
              Delete Cluster
            </Button>
          )}
          <SelectorNodo cluster={estado} value={nodo} onChange={setNodo} label="Cluster Node" /></>}
      />

      {cargando ? (
        <Loading />
      ) : !inicializado ? (
        <Empty
          titulo="Cluster Not Initialized"
          acciones={
            <>
              <Button variant="primary" onClick={() => setModal({ tipo: 'new' })}>
                New Cluster
              </Button>
              <Button onClick={() => setModal({ tipo: 'join' })}>Join Cluster</Button>
            </>
          }
        >
          This server is not part of a cluster. Create one, or join an existing cluster.
        </Empty>
      ) : (
        <>
          <Tabla
            cabecera={
              <>
                <Th campo="name" orden={orden} onOrdenar={alternar}>Node Name</Th>
                <Th campo="ip" orden={orden} onOrdenar={alternar}>IP Address</Th>
                <Th campo="url" orden={orden} onOrdenar={alternar}>URL</Th>
                <Th campo="type" orden={orden} onOrdenar={alternar}>Type</Th>
                <Th campo="state" orden={orden} onOrdenar={alternar}>State</Th>
                <Th campo="upSince" orden={orden} onOrdenar={alternar}>Up Since</Th>
                <Th campo="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                <Th campo="synced" orden={orden} onOrdenar={alternar}>Last Synced</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            vacia={nodosVisibles.length === 0}
            vacio="No Node Found"
            columnas={9}
          >
            {nodosVisibles.map((n) => (
              <tr key={n.id}>
                <td>{n.name}</td>
                <td className={styles.mono}>
                  {n.ipAddresses.map((ip) => (
                    <div key={ip}>{ip}</div>
                  ))}
                </td>
                <td className={styles.mono}>{n.url}</td>
                <td>
                  {n.type === 'Primary' || n.type === 'Secondary' ? (
                    <Tag tone="info">{n.type}</Tag>
                  ) : (
                    <Tag tone="warn">Unknown</Tag>
                  )}
                </td>
                <td>
                  {n.state === 'Self' ? (
                    <Tag>Self</Tag>
                  ) : n.state === 'Connected' ? (
                    <Tag tone="ok">Connected</Tag>
                  ) : n.state === 'Unreachable' ? (
                    <Tag tone="warn">Unreachable</Tag>
                  ) : (
                    <Tag tone="warn">Unknown</Tag>
                  )}
                </td>
                <td className={styles.nowrap}>
                  <FechaRelativa iso={n.upSince} />
                </td>
                <td className={styles.nowrap}>
                  {/* El nodo propio no tiene «Last Seen»: en su fila esa
                      columna va siempre vacía (cluster.js:177-193). */}
                  {n.state !== 'Self' && <FechaRelativa iso={n.lastSeen} />}
                </td>
                <td className={styles.nowrap}>
                  {n.state === 'Self' && n.type === 'Secondary' && (
                    <FechaRelativa iso={n.configLastSynced} />
                  )}
                </td>
                <td className={tbl.celdaAcciones}>
                  <div className={tbl.acciones}>
                    {/* Qué se puede hacer con un nodo depende de si esta
                        consola habla con el primario o con un secundario
                        (cluster.js:248-264). Editar es lo frecuente y va en
                        la fila; quitar y promocionar, dentro del menú. */}
                    {(esPrimario ? n.state === 'Self' : n.state === 'Self' || n.type === 'Primary') && (
                      <AccionFila
                        icono="editar"
                        nombre="Edit Node"
                        onClick={() =>
                          setModal({
                            tipo: n.state === 'Self' ? 'editSelf' : 'editPrimary',
                            nodo: n,
                          })
                        }
                      />
                    )}
                    {((esPrimario && n.type === 'Secondary') ||
                      (tipoPropio === 'Secondary' && n.state === 'Self')) && (
                      <Menu etiqueta={`Actions for ${n.name}`}>
                        {(cerrar) => (
                          <>
                            {tipoPropio === 'Secondary' && n.state === 'Self' && (
                              <button type="button" onClick={() => { cerrar(); setModal({ tipo: 'promote', nodo: n }) }}>
                                Promote To Primary
                              </button>
                            )}
                            {esPrimario && n.type === 'Secondary' && (
                              <>
                                <Separador />
                                <button type="button" data-variant="danger" onClick={() => { cerrar(); setModal({ tipo: 'remove', nodo: n }) }}>
                                  Remove Node
                                </button>
                              </>
                            )}
                          </>
                        )}
                      </Menu>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </Tabla>
          <div className={styles.count}>
            <span>{`Total Nodes: ${nodos.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={modal?.tipo === 'resync'}
        titulo="Resync Cluster"
        texto={
          <>
            The resync Cluster action will initiate a full config transfer from the Primary node.
            You will need to check the logs to confirm if the resync action was successful.
            <br />
            <br />
            Are you sure you want to resync the Cluster config?
          </>
        }
        etiqueta="Resync"
        variante="primary"
        onCerrar={() => setModal(null)}
        onConfirmar={() => void lanzarResync()}
      />

      {modal?.tipo === 'new' && (
        <NuevoCluster
          token={token}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Cluster Initialized!',
              text: 'A new cluster was initialized successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'join' && (
        <UnirseCluster
          token={token}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Joined Cluster!',
              text: 'Joined the cluster successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'options' && (
        <OpcionesCluster
          token={token}
          nodo={nodo}
          onCerrar={() => setModal(null)}
          onHecho={() => {
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Options Saved!',
              text: 'The Cluster options were saved successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'editSelf' && (
        <EditarNodoPropio
          token={token}
          nodo={nodo}
          objetivo={modal.nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Node Updated!',
              text: 'Cluster node was updated successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'editPrimary' && (
        <EditarNodoPrimario
          token={token}
          nodo={nodo}
          objetivo={modal.nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Node Updated!',
              text: 'Cluster node was updated successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'remove' && (
        <QuitarNodo
          token={token}
          nodo={nodo}
          objetivo={modal.nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Node Removed!',
              text: 'Cluster node was removed successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'promote' && (
        <PromocionarNodo
          token={token}
          nodo={nodo}
          objetivo={modal.nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Promoted!',
              text: 'The selected node was successfully promoted to Primary node in the Cluster.',
            })
          }}
        />
      )}

      {modal?.tipo === 'leave' && (
        <DejarCluster
          token={token}
          nodo={nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Left Cluster!',
              text: 'Left the Cluster successfully.',
            })
          }}
        />
      )}

      {modal?.tipo === 'delete' && (
        <BorrarCluster
          token={token}
          nodo={nodo}
          onCerrar={() => setModal(null)}
          onHecho={(s) => {
            recargarCon(s)
            setModal(null)
            onAviso({
              type: 'success',
              title: 'Cluster Deleted!',
              text: 'Cluster was deleted successfully.',
            })
          }}
        />
      )}
    </>
  )
}

function FechaRelativa({ iso }: { iso?: string }) {
  if (iso == null) return null
  return (
    <>
      <div className={styles.mono}>{fechaMinuto(iso)}</div>
      <div className={styles.meta}>{`(${desdeAhora(iso)})`}</div>
    </>
  )
}

/*
«Quick Add» (cluster.js:21-72). Añade la IP elegida al final de la lista SÓLO si
su texto no aparece ya en ella. La comparación es por subcadena: es lo que hace
`indexOf` y se replica tal cual.
*/
function QuickAdd({
  ips,
  onAnadir,
  label,
}: {
  ips: string[]
  onAnadir: (ip: string) => void
  label: string
}) {
  const [valor, setValor] = useState('')
  const id = useId()
  return (
    <div className={styles.ctlLine}>
      <label className={styles.suffix} htmlFor={id}>
        {label}
      </label>
      <Select
        id={id}
        className={styles.select}
        value={valor}
        onChange={(e) => {
          setValor(e.target.value)
          if (e.target.value !== '') onAnadir(e.target.value)
        }}
      >
        <option value="" />
        {ips.map((ip) => (
          <option key={ip} value={ip}>
            {ip}
          </option>
        ))}
      </Select>
    </div>
  )
}

function anadirIp(lista: string, ip: string): string {
  return lista.indexOf(ip) < 0 ? `${lista}${ip}\n` : lista
}

/** `showInitializeClusterModal` / `initializeNewCluster` (cluster.js:548-645). */
function NuevoCluster({
  token,
  onCerrar,
  onHecho,
}: {
  token: string | null
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [cargando, setCargando] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [dominio, setDominio] = useState('')
  const [lista, setLista] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setCargando(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      if (outcome.data.response.clusterInitialized) {
        setYaEsta(true)
        setAviso({ type: 'danger', title: 'Error!', text: 'Cluster is already initialized.' })
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token])

  async function inicializar() {
    if (dominio === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Cluster domain name.' })
      return
    }
    const limpia = limpiarLista(lista)
    if (limpia.length === 0 || limpia === ',') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a Primary node IP address.',
      })
      return
    }

    setOcupado(true)
    const outcome = await initCluster(token, dominio, limpia)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Initialize New Cluster"
      tamano="medio"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado || cargando || yaEsta} onClick={() => void inicializar()}>
            Initialize
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      {cargando ? (
        <Loading />
      ) : yaEsta ? null : (
        <>
          <p className={styles.parrafo}>
            The initialization of a new Cluster will make the current DNS Server its Primary node.
            You can add other DNS Servers to this Cluster later which will get added as Secondary
            nodes. No data will be lost on this DNS Server in this process.
          </p>

          <MRow
            label="Cluster Domain"
            help="The fully qualified domain name to be used to identify the new Cluster."
          >
            {(id) => (
              <Input
                id={id}
                placeholder="domain name"
                maxLength={255}
                value={dominio}
                onChange={(e) => setDominio(e.target.value)}
              />
            )}
          </MRow>

          <MRow
            label="Primary Node IP Addresses"
            help="The static IP addresses of this DNS Server that will be accessible by all other DNS Servers to be added later as Secondary nodes. Enter IP addresses one below another in the above text field or use the Quick Add list to add available IP addresses on the server."
          >
            {(id) => (
              <>
                <Textarea
                  mono
                  id={id}
                  className={styles.area}
                  rows={3}
                  spellCheck={false}
                  value={lista}
                  onChange={(e) => setLista(e.target.value)}
                />
                <QuickAdd
                  ips={ips}
                  label="Quick Add"
                  onAnadir={(ip) => setLista((t) => anadirIp(t, ip))}
                />
              </>
            )}
          </MRow>

          <Alert type="info" title="Note!">
            When the Cluster is initialized, the DNS Server Domain Name will be changed such that the
            current hostname is a subdomain name of the Cluster Domain name specified above. For
            example, if the current DNS Server Domain Name is <code>ns1.mydomain.tld</code> or just{' '}
            <code>ns1</code> then the new domain name will be <code>ns1.mycluster.tld</code>.
          </Alert>
          <Alert type="info" title="Note!">
            If the Web Service does not have HTTPS enabled, then the initialization process will
            enable it automatically with a self-signed certificate. However, it is recommended to
            manually configure HTTPS with a valid certificate before initializing the Cluster. This
            certificate must include the new expected DNS Server Domain Name, as mentioned in the
            above note, as the Subject Common Name or Subject Alternative Name (SAN) so that it
            validates when a Secondary node tries to join the Cluster. Once a node joins the Cluster,
            it uses DANE-EE for server authentication and the domain name in the certificate is no
            longer required to match the DNS Server Domain Name.
          </Alert>
          <Alert type="info" title="Note!">
            The initialization process will create two zones if they do not exist. The first zone
            will be the Cluster Primary zone named as the Cluster Domain name specified above where
            the Cluster will automatically manage domain name records for all the nodes. The second
            zone will be the Cluster Catalog zone that uses <code>cluster-catalog</code> as the
            subdomain name of the Cluster Domain name. Use this Cluster Catalog zone for automatic
            provisioning of Secondary zones on all of the Cluster Secondary nodes.
          </Alert>
          <Alert type="warning" title="Warning!">
            The Cluster Domain name cannot be changed later. Make sure that you enter the correct
            domain name before proceeding. You can update the DNS Server Domain Name later if needed
            from Settings but it must always be a subdomain name of the Cluster Domain name.
          </Alert>
          <div className={styles.enlace}>
            <a
              href="https://blog.technitium.com/2025/11/understanding-clustering-and-how-to.html"
              target="_blank"
              rel="noreferrer"
            >
              Help: Understanding Clustering And How To Configure It
            </a>
          </div>
        </>
      )}
    </Dialog>
  )
}

/** `showInitializeJoinClusterModal` / `initializeJoinCluster` (cluster.js:647-760). */
function UnirseCluster({
  token,
  onCerrar,
  onHecho,
}: {
  token: string | null
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [cargando, setCargando] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [lista, setLista] = useState('')
  const [url, setUrl] = useState('')
  const [ip, setIp] = useState('')
  const [ignorar, setIgnorar] = useState('false')
  const [usuario, setUsuario] = useState('admin')
  const [pass, setPass] = useState('')
  const [totp, setTotp] = useState('')
  const [pideTotp, setPideTotp] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setCargando(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      if (outcome.data.response.clusterInitialized) {
        setYaEsta(true)
        setAviso({ type: 'danger', title: 'Error!', text: 'Cluster is already initialized.' })
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token])

  async function unirse() {
    const limpia = limpiarLista(lista)
    if (limpia.length === 0 || limpia === ',') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please select a Secondary node IP address.',
      })
      return
    }
    if (url === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Primary node URL.' })
      return
    }
    if (usuario === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the Primary node admin username.',
      })
      return
    }
    if (pass === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the Primary node admin password.',
      })
      return
    }
    // El OTP sólo se exige cuando el campo está a la vista, y sólo se pone a la
    // vista después de que el servidor conteste `2fa-required`.
    if (pideTotp && totp === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: "Please enter the Primary node admin user's OTP.",
      })
      return
    }

    setOcupado(true)
    const outcome = await initJoinCluster(token, {
      secondaryNodeIpAddresses: limpia,
      primaryNodeUrl: url,
      primaryNodeIpAddress: ip,
      ignoreCertificateErrors: ignorar,
      primaryNodeUsername: usuario,
      primaryNodePassword: pass,
      primaryNodeTotp: totp,
    })
    setOcupado(false)

    if (outcome.kind === 'two-factor-required') {
      setPideTotp(true)
      return
    }
    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Join Cluster"
      tamano="medio"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado || cargando || yaEsta} onClick={() => void unirse()}>
            Join
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      {cargando ? (
        <Loading />
      ) : yaEsta ? null : (
        <>
          <p className={styles.parrafo}>
            Joining a Cluster will make this DNS Server its Secondary node. This process will
            overwrite configuration on this DNS Server for Allowed, Blocked, Apps, Settings and
            Administration sections. The DNS Server will automatically synchronize its configuration
            with the Primary node in the Cluster.
          </p>

          <MRow
            label="Secondary Node IP Addresses"
            help="The static IP addresses of this DNS Server that will be accessible by all other DNS Server nodes in the Cluster. Enter IP addresses one below another in the above text field or use the Quick Add list to add available IP addresses on the server."
          >
            {(id) => (
              <>
                <Textarea
                  mono
                  id={id}
                  className={styles.area}
                  rows={3}
                  spellCheck={false}
                  value={lista}
                  onChange={(e) => setLista(e.target.value)}
                />
                <QuickAdd
                  ips={ips}
                  label="Quick Add"
                  onAnadir={(v) => setLista((t) => anadirIp(t, v))}
                />
              </>
            )}
          </MRow>

          <MRow
            label="Primary Node URL"
            help="The Web Service HTTPS URL of the Primary node in the Cluster."
          >
            {(id) => (
              <Input
                id={id}
                placeholder="URL"
                maxLength={255}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            )}
          </MRow>

          <MRow
            label="Primary Node IP Address (Optional)"
            help="The IP address of the Primary node in the Cluster. When unspecified, domain name in the Primary node URL will be resolved and used."
          >
            {(id) => (
              <Input
                id={id}
                placeholder="IP address"
                maxLength={255}
                value={ip}
                onChange={(e) => setIp(e.target.value)}
              />
            )}
          </MRow>

          {/* Iba con `frm.rowCtl` —la columna de una fila de PÁGINA— dentro de un
              modal, que es el mismo descuido que tenía `MRow`. */}
          <GroupRow modal label="Certificate Validation">
            <Radios
              name="joinClusterCertificateValidation"
              value={ignorar}
              onChange={setIgnorar}
              options={[
                {
                  value: 'false',
                  label: 'Validate Certificate With PKI and DANE (Recommended)',
                  help: 'The Primary node Web Service TLS certificate will be validated using PKI and DANE to ensure that your connection is secure.',
                },
                {
                  value: 'true',
                  label: 'Ignore Certificate Validation Errors',
                  help: 'Use this options only when you know that the Primary node Web Service is using a self-signed TLS certificate and is reachable on a private network.',
                },
              ]}
            />
          </GroupRow>

          <MRow
            label="Primary Node Username"
            help="The username of an administrator on the Primary node in the Cluster."
          >
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

          <MRow label="Primary Node Password" help="The password of the administrator user specified above.">
            {(id) => (
              <Input
                id={id}
                type="password"
                maxLength={255}
                disabled={pideTotp}
                value={pass}
                onChange={(e) => setPass(e.target.value)}
              />
            )}
          </MRow>

          {pideTotp && (
            <MRow
              label="Primary Node OTP"
              help="Enter the 6-digit code you see in your authenticator app for the administrator user specified above."
            >
              {(id) => (
                <Input
                  id={id}
                  placeholder="OTP"
                  maxLength={6}
                  autoComplete="off"
                  value={totp}
                  onChange={(e) => setTotp(e.target.value)}
                />
              )}
            </MRow>
          )}

          <Alert type="info" title="Note!">
            The process to join the Cluster may take a while to complete depending on the amount of
            initial config data that needs to be synchronized from the Primary node. Please be
            patient till the process completes.
          </Alert>
          <Alert type="info" title="Note!">
            If the Web Service does not have HTTPS enabled, then the joining process will enable it
            automatically with a self-signed certificate. However, its recommended to manually
            configure HTTPS with a valid certificate before joining the cluster. This certificate
            should optionally include the new expected DNS Server Domain Name, which will be a
            subdomain name of the Cluster Domain name, as the Subject Common Name or Subject
            Alternative Name (SAN).
          </Alert>
          <Alert type="info" title="Note!">
            The Ignore Certificate Validation Errors option when selected is used only for the
            initial connection to the Primary node during the joining process. Once the DNS Server
            joins the Cluster, it will always use DANE-EE for authentication using the TLSA records
            in the Cluster Primary zone that are added for each node in the Cluster.
          </Alert>
          <Alert type="warning" title="Warning!">
            Joining a Cluster will cause configuration on this DNS Server to be overwritten
            permanently for Allowed, Blocked, Apps, Settings and Administration sections!
          </Alert>
          <div className={styles.enlace}>
            <a
              href="https://blog.technitium.com/2025/11/understanding-clustering-and-how-to.html"
              target="_blank"
              rel="noreferrer"
            >
              Help: Understanding Clustering And How To Configure It
            </a>
          </div>
        </>
      )}
    </Dialog>
  )
}

/*
`showClusterOptionsModal` / `saveClusterOptions` (cluster.js:786-928). Los cuatro
intervalos sólo se pueden TOCAR desde el nodo primario; desde un secundario el
modal sale de sólo lectura y sin botón de guardar. El dominio del cluster está
siempre bloqueado: no se puede cambiar nunca.
*/
function OpcionesCluster({
  token,
  nodo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  onCerrar: () => void
  onHecho: () => void
}) {
  const [cargando, setCargando] = useState(true)
  const [esPrimario, setEsPrimario] = useState(false)
  const [dominio, setDominio] = useState('')
  const [hbRefresh, setHbRefresh] = useState('')
  const [hbRetry, setHbRetry] = useState('')
  const [cfgRefresh, setCfgRefresh] = useState('')
  const [cfgRetry, setCfgRetry] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: nodo }).then((outcome) => {
      if (!vivo) return
      setCargando(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      const r = outcome.data.response
      setEsPrimario(r.clusterNodes?.find((n) => n.state === 'Self')?.type === 'Primary')
      setDominio(r.clusterDomain ?? '')
      setHbRefresh(String(r.heartbeatRefreshIntervalSeconds ?? ''))
      setHbRetry(String(r.heartbeatRetryIntervalSeconds ?? ''))
      setCfgRefresh(String(r.configRefreshIntervalSeconds ?? ''))
      setCfgRetry(String(r.configRetryIntervalSeconds ?? ''))
    })
    return () => {
      vivo = false
    }
  }, [token, nodo])

  async function guardar() {
    if (hbRefresh === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Heartbeat Refresh Interval.',
      })
      return
    }
    if (hbRetry === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Heartbeat Retry Interval.',
      })
      return
    }
    if (cfgRefresh === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Config Refresh Interval.',
      })
      return
    }
    if (cfgRetry === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Config Retry Interval.',
      })
      return
    }

    setOcupado(true)
    const outcome = await setClusterOptions(
      token,
      {
        heartbeatRefreshIntervalSeconds: hbRefresh,
        heartbeatRetryIntervalSeconds: hbRetry,
        configRefreshIntervalSeconds: cfgRefresh,
        configRetryIntervalSeconds: cfgRetry,
      },
      nodo,
    )
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho()
  }

  const intervalos: [string, string, string, (v: string) => void, string][] = [
    ['Heartbeat Refresh Interval', hbRefresh, 'seconds (valid range 10-300; default 30)', setHbRefresh,
      'The interval in seconds in which the DNS Server must refresh the state of all nodes in the Cluster.'],
    ['Heartbeat Retry Interval', hbRetry, 'seconds (valid range 10-300; default 10)', setHbRetry,
      'The interval in seconds in which the DNS Server must retry the state refresh process for all nodes in case of a failure.'],
    ['Config Refresh Interval', cfgRefresh, 'seconds (valid range 30-3600; default 900)', setCfgRefresh,
      'The interval in seconds in which the DNS Server must refresh the configuration from the Primary node.'],
    ['Config Retry Interval', cfgRetry, 'seconds (valid range 30-3600; default 60)', setCfgRetry,
      'The interval in seconds in which the DNS Server must retry the configuration refresh process for the Primary node in case of a failure.'],
  ]

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Cluster Options"
      tamano="medio"
      acciones={
        <>
          {esPrimario && (
            <Button variant="primary" disabled={ocupado || cargando} onClick={() => void guardar()}>
              Save
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
      {cargando ? (
        <Loading />
      ) : (
        <>
          <MRow label="Cluster Domain" help="The fully qualified domain name of the Cluster.">
            {(id) => <Input id={id} placeholder="domain name" value={dominio} disabled readOnly />}
          </MRow>
          {intervalos.map(([label, valor, sufijo, set, ayuda]) => (
            <MRow key={label} label={label} help={ayuda}>
              {(id) => (
                <div className={styles.ctlLine}>
                  <Input
                    id={id}
                    type="number"
                    placeholder="seconds"
                    style={{ width: 100 }}
                    disabled={!esPrimario}
                    value={valor}
                    onChange={(e) => set(e.target.value)}
                  />
                  <span className={styles.suffix}>{sufijo}</span>
                </div>
              )}
            </MRow>
          ))}
        </>
      )}
    </Dialog>
  )
}

/** `showEditSelfClusterNodeModal` / `updateSelfClusterNode` (cluster.js:274-361). */
function EditarNodoPropio({
  token,
  nodo,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [cargando, setCargando] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [lista, setLista] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: nodo, includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setCargando(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token, nodo])

  async function guardar() {
    const limpia = limpiarLista(lista)
    if (limpia.length === 0 || limpia === ',') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a node IP address.' })
      return
    }

    setOcupado(true)
    const outcome = await updateIpAddress(token, limpia, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title={`Edit Node - ${objetivo.name}`}
      tamano="medio"
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
      {cargando ? (
        <Loading />
      ) : (
        <MRow
          label="Node IP Addresses"
          help="The static IP addresses of this DNS Server that will be accessible by all other DNS Server nodes in the Cluster. Enter IP addresses one below another in the above text field or use the Quick Add list to add available IP addresses on the server."
        >
          {(id) => (
            <>
              <Textarea
                mono
                id={id}
                className={styles.area}
                rows={3}
                spellCheck={false}
                value={lista}
                onChange={(e) => setLista(e.target.value)}
              />
              <QuickAdd ips={ips} label="Quick Add" onAnadir={(ip) => setLista((t) => anadirIp(t, ip))} />
            </>
          )}
        </MRow>
      )}
    </Dialog>
  )
}

/** `showEditPrimaryClusterNodeModal` / `updatePrimaryClusterNode` (cluster.js:363-432).
 *  No carga nada: sale con lo que ya había en la fila. */
function EditarNodoPrimario({
  token,
  nodo,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [url, setUrl] = useState(objetivo.url)
  const [lista, setLista] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function guardar() {
    if (url === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Primary node URL.' })
      return
    }
    // Aquí la lista SÍ puede quedar vacía: es opcional. Upstream sólo normaliza
    // el caso degenerado de una coma suelta (cluster.js:400).
    let limpia = limpiarLista(lista)
    if (limpia === ',') limpia = ''

    setOcupado(true)
    const outcome = await updatePrimaryNode(token, url, limpia, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title={`Edit Node - ${objetivo.name}`}
      tamano="medio"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void guardar()}>
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
      <MRow label="Primary Node URL" help="The Web Service HTTPS URL of the Primary node in the Cluster.">
        {(id) => (
          <Input
            id={id}
            placeholder="URL"
            maxLength={255}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        )}
      </MRow>
      <MRow
        label="Primary Node IP Addresses (Optional)"
        help="The IP addresses of the Primary node in the Cluster. When unspecified, domain name in the Primary node URL will be resolved and used."
      >
        {(id) => (
          <Textarea
            mono
            id={id}
            className={styles.area}
            rows={3}
            spellCheck={false}
            value={lista}
            onChange={(e) => setLista(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/** `showRemoveSecondaryClusterNodeModal` / `removeSecondaryClusterNode`
 *  (cluster.js:434-495). La casilla cambia el ENDPOINT, no un parámetro. */
function QuitarNodo({
  token,
  nodo,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function quitar() {
    setOcupado(true)
    const id = String(objetivo.id)
    const outcome = forzar
      ? await deleteSecondaryNode(token, id, nodo)
      : await removeSecondaryNode(token, id, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title={`Remove Node - ${objetivo.name}`}
      acciones={
        <>
          <Button variant="danger" disabled={ocupado} onClick={() => void quitar()}>
            Remove
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <p className={styles.parrafo}>
        The Remove Node process will ask the selected Secondary node to leave the Cluster gracefully.
        The Secondary will then initiate Leave Cluster process as if the Leave Cluster action was
        performed on that node itself.
      </p>
      <Check
        conmutador
        label="Force Remove Node"
        checked={forzar}
        onChange={setForzar}
        help="Enabling this option will cause the Secondary node to be deleted from the Cluster without asking the node to leave gracefully."
      />
      <p className={styles.parrafo}>
        Are you sure you want to remove the Secondary node from the Cluster?
      </p>
      <Alert type="info" title="Note!">
        Use the Force Remove Node option only when the Secondary node is unreachable/decommissioned
        and cannot leave the Cluster gracefully.
      </Alert>
    </Dialog>
  )
}

/** `showPromoteToPrimaryClusterNodeModal` / `promoteToPrimaryClusterNode`
 *  (cluster.js:497-546). */
function PromocionarNodo({
  token,
  nodo,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function promocionar() {
    setOcupado(true)
    const outcome = await promoteToPrimary(token, forzar, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title={`Promote To Primary Node - ${objetivo.name}`}
      acciones={
        <>
          <Button variant="danger" disabled={ocupado} onClick={() => void promocionar()}>
            Promote
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <p className={styles.parrafo}>
        The promote To Primary node process will resync complete configuration from the Primary node
        and then proceed to delete it from the Cluster followed by upgrading the selected Secondary
        node to become the Primary node in the Cluster. The former Primary node when deleted will
        cause it to delete all its own Cluster configuration leaving the Cluster without causing any
        other data loss.
      </p>
      <Check
        conmutador
        label="Force Delete Current Primary Node"
        checked={forzar}
        onChange={setForzar}
        help="Enabling this option will cause the current Primary node to be deleted from the Cluster without resyncing complete configuration from it and without inform it."
      />
      <p className={styles.parrafo}>
        Are you sure you want to promote the selected Secondary node to become the Primary node in
        the Cluster?
      </p>
      <Alert type="info" title="Note!">
        Use the Force Delete Current Primary Node option only when the Primary node is
        unreachable/decommissioned and thus cannot be deleted from the Cluster gracefully.
      </Alert>
      <Alert type="info" title="Note!">
        The process to promote to Primary node may take a while to complete depending on the size of
        the complete configuration being resynced and the number of local zones that need to be
        converted. Please be patient till the process completes.
      </Alert>
    </Dialog>
  )
}

/** `showLeaveClusterModal` / `leaveCluster` (cluster.js:918-973). */
function DejarCluster({
  token,
  nodo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function salir() {
    setOcupado(true)
    const outcome = await leaveCluster(token, forzar, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Leave Cluster"
      acciones={
        <>
          <Button variant="danger" disabled={ocupado} onClick={() => void salir()}>
            Leave
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <p className={styles.parrafo}>
        The Leave Cluster process will remove all Cluster configuration from this Secondary node and
        leave the Cluster gracefully. There will be no data loss except for the Cluster
        configuration. You will need to re-join the Cluster again to use this DNS Server as a
        Secondary node.
      </p>
      <Check
        conmutador
        label="Force Leave Cluster"
        checked={forzar}
        onChange={setForzar}
        help="Enabling this option will cause this Secondary node to leave the Cluster without informing the Primary node."
      />
      <p className={styles.parrafo}>Are you sure you want to leave the Cluster?</p>
      <Alert type="info" title="Note!">
        Use the Force Leave Cluster option only when the Primary node is unreachable/decommissioned
        and thus cannot leave the Cluster gracefully.
      </Alert>
    </Dialog>
  )
}

/** `showDeleteClusterModal` / `deleteCluster` (cluster.js:961-1011). */
function BorrarCluster({
  token,
  nodo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  nodo: string
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function borrar() {
    setOcupado(true)
    const outcome = await deleteCluster(token, forzar, nodo)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Delete Cluster"
      acciones={
        <>
          <Button variant="danger" disabled={ocupado} onClick={() => void borrar()}>
            Delete
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <p className={styles.parrafo}>
        The Delete Cluster process will remove all Cluster configuration from this Primary node.
        There will be no data loss except for the Cluster configuration. You will need to
        re-initialize the Cluster again to use clustering features on this DNS Server.
      </p>
      <Check
        conmutador
        label="Force Delete Cluster"
        checked={forzar}
        onChange={setForzar}
        help="Enabling this option will cause this Primary node to delete the Cluster for itself even when other Secondary nodes still exist, orphaning them."
      />
      <p className={styles.parrafo}>Are you sure you want to delete the Cluster?</p>
      <Alert type="info" title="Note!">
        You can delete the Cluster only when there are no Secondary nodes in the Cluster. Use the
        Force Delete Cluster option only when you wish this Primary node to be removed from the
        Cluster even when there are Secondary nodes in the Cluster. In this case, the Secondary nodes
        will become orphaned and you will need to promote one of them to be the new Primary node
        manually.
      </Alert>
    </Dialog>
  )
}
