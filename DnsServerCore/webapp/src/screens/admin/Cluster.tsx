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
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu, Separador } from '../../ui/Menu'
import { GroupRow } from '../../ui/Form'
import { Avisador } from '../../ui/Avisador'

/*
The Cluster sub-tab (the whole of `cluster.js`, 1,055 lines). Twelve endpoints
and eight modals.

What to keep in front of you:

  · **The cluster's state rules the action bar.** With no cluster only
    initialising is offered; with a cluster, the node ITSELF decides: if it is
    primary, "Options" and "Delete Cluster" show, and if it is secondary,
    "Resync", "Options" and "Leave Cluster" (cluster.js:248-264). It is not
    cosmetic: the endpoints behind them only exist on one side.
  · **Each ROW's actions also depend on the node itself**, and not on the row: a
    primary can edit itself and remove secondaries; a secondary can edit itself,
    promote itself, and edit the primary's entry (cluster.js:207-238).
  · **"Quick Add" compares by SUBSTRING**, not by line (cluster.js:30): with
    `10.0.0.1` already in the list, adding `10.0.0.10` does nothing. The
    behaviour is replicated, not the intent.
  · **"Force Remove Node" changes the endpoint**, not a parameter:
    `primary/deleteSecondary` with the box checked and `primary/removeSecondary`
    without it.
  · **`secondary/resync` does not return the cluster's state**: an alert is shown
    and it points at the Logs.

Verification notice: with a single instance the cluster never gets initialised,
so half of these endpoints could not be exercised against a real server. They are
written against `cluster.js` and against `WebServiceClusterApi.cs`, and covered
with tests over simulated responses.
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
  | { tipo: 'editSelf'; node: ClusterNode }
  | { tipo: 'editPrimary'; node: ClusterNode }
  | { tipo: 'remove'; node: ClusterNode }
  | { tipo: 'promote'; node: ClusterNode }
  | { tipo: 'leave' }
  | { tipo: 'delete' }
  | { tipo: 'resync' }

/* `sortTable('tbodyAdminCluster', 0..7)`. The three dates are read by their ISO:
   the cell draws the date and the "time ago", and both sort the same. */
const KEYS: Keys<ClusterNode> = {
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
  const [node, setNodo] = useState('')
  const [state, setEstado] = useState<ClusterState | null>(cluster)
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState<Modal | null>(null)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await getClusterState(token, { node: node })
    setLoading(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setEstado(outcome.data.response)
    onCluster(outcome.data.response)
  }, [token, node, onCluster, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])


  function recargarCon(s: ClusterState) {
    setEstado(s)
    onCluster(s)
  }

  const nodes = state?.clusterNodes ?? []
  const { rows: nodosVisibles, orden, alternar } = useOrden(KEYS, nodes)
  const tipoPropio = nodes.find((n) => n.state === 'Self')?.type
  const initialised = state?.clusterInitialized === true
  const esPrimario = tipoPropio === 'Primary'

  async function lanzarResync() {
    setModal(null)
    const outcome = await resyncCluster(token, node)
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
        section="Administration"
        titulo="Cluster"
        actions={<>{initialised && !esPrimario && (
            <Button variant="primary" onClick={() => setModal({ tipo: 'resync' })}>
              Resync
            </Button>
          )}
          {initialised && (
            <Button variant="primary" onClick={() => setModal({ tipo: 'options' })}>
              Options
            </Button>
          )}
          {initialised && !esPrimario && (
            <Button onClick={() => setModal({ tipo: 'leave' })}>Leave Cluster</Button>
          )}
          {initialised && esPrimario && (
            <Button variant="danger" onClick={() => setModal({ tipo: 'delete' })}>
              Delete Cluster
            </Button>
          )}
          <SelectorNodo cluster={state} value={node} onChange={setNodo} label="Cluster Node" /></>}
      />

      {loading ? (
        <Loading />
      ) : !initialised ? (
        <Empty
          titulo="Cluster Not Initialized"
          actions={
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
          <Table
            header={
              <>
                <Th field="name" orden={orden} onOrdenar={alternar}>Node Name</Th>
                <Th field="ip" orden={orden} onOrdenar={alternar}>IP Address</Th>
                <Th field="url" orden={orden} onOrdenar={alternar}>URL</Th>
                <Th field="type" orden={orden} onOrdenar={alternar}>Type</Th>
                <Th field="state" orden={orden} onOrdenar={alternar}>State</Th>
                <Th field="upSince" orden={orden} onOrdenar={alternar}>Up Since</Th>
                <Th field="lastSeen" orden={orden} onOrdenar={alternar}>Last Seen</Th>
                <Th field="synced" orden={orden} onOrdenar={alternar}>Last Synced</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            isEmpty={nodosVisibles.length === 0}
            emptyText="No Node Found"
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
                  {/* The node itself has no "Last Seen": in its row that column
                      is always empty (cluster.js:177-193). */}
                  {n.state !== 'Self' && <FechaRelativa iso={n.lastSeen} />}
                </td>
                <td className={styles.nowrap}>
                  {n.state === 'Self' && n.type === 'Secondary' && (
                    <FechaRelativa iso={n.configLastSynced} />
                  )}
                </td>
                <td className={tbl.celdaAcciones}>
                  <div className={tbl.actions}>
                    {/* What can be done with a node depends on whether this
                        console is talking to the primary or to a secondary
                        (cluster.js:248-264). Editing is the frequent one and goes
                        in the row; removing and promoting, inside the menu. */}
                    {(esPrimario ? n.state === 'Self' : n.state === 'Self' || n.type === 'Primary') && (
                      <AccionFila
                        icono="editar"
                        name="Edit Node"
                        onClick={() =>
                          setModal({
                            tipo: n.state === 'Self' ? 'editSelf' : 'editPrimary',
                            node: n,
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
                              <button type="button" onClick={() => { cerrar(); setModal({ tipo: 'promote', node: n }) }}>
                                Promote To Primary
                              </button>
                            )}
                            {esPrimario && n.type === 'Secondary' && (
                              <>
                                <Separador />
                                <button type="button" data-variant="danger" onClick={() => { cerrar(); setModal({ tipo: 'remove', node: n }) }}>
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
          </Table>
          <div className={styles.count}>
            <span>{`Total Nodes: ${nodes.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={modal?.tipo === 'resync'}
        titulo="Resync Cluster"
        text={
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
          node={node}
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
          node={node}
          objetivo={modal.node}
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
          node={node}
          objetivo={modal.node}
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
          node={node}
          objetivo={modal.node}
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
          node={node}
          objetivo={modal.node}
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
          node={node}
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
          node={node}
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
"Quick Add" (cluster.js:21-72). Appends the chosen IP to the end of the list
ONLY if its text does not already appear in it. The comparison is by substring:
that is what `indexOf` does and it is replicated as it stands.
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
  const [value, setValor] = useState('')
  const id = useId()
  return (
    <div className={styles.ctlLine}>
      <label className={styles.suffix} htmlFor={id}>
        {label}
      </label>
      <Select
        id={id}
        className={styles.select}
        value={value}
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

function anadirIp(list: string, ip: string): string {
  return list.indexOf(ip) < 0 ? `${list}${ip}\n` : list
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
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [dominio, setDominio] = useState('')
  const [list, setLista] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
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
    const limpia = limpiarLista(list)
    if (limpia.length === 0 || limpia === ',') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a Primary node IP address.',
      })
      return
    }

    setBusy(true)
    const outcome = await initCluster(token, dominio, limpia)
    setBusy(false)

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
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading || yaEsta} onClick={() => void inicializar()}>
            Initialize
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      {loading ? (
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
                  value={list}
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
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [list, setLista] = useState('')
  const [url, setUrl] = useState('')
  const [ip, setIp] = useState('')
  const [ignorar, setIgnorar] = useState('false')
  const [user, setUsuario] = useState('admin')
  const [pass, setPass] = useState('')
  const [totp, setTotp] = useState('')
  const [pideTotp, setPideTotp] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
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
    const limpia = limpiarLista(list)
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
    if (user === '') {
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
    // The OTP is only required when the field is in sight, and it is only put in
    // sight after the server answers `2fa-required`.
    if (pideTotp && totp === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: "Please enter the Primary node admin user's OTP.",
      })
      return
    }

    setBusy(true)
    const outcome = await initJoinCluster(token, {
      secondaryNodeIpAddresses: limpia,
      primaryNodeUrl: url,
      primaryNodeIpAddress: ip,
      ignoreCertificateErrors: ignorar,
      primaryNodeUsername: user,
      primaryNodePassword: pass,
      primaryNodeTotp: totp,
    })
    setBusy(false)

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
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading || yaEsta} onClick={() => void unirse()}>
            Join
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      {loading ? (
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
                  value={list}
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

          {/* It went with `frm.rowCtl` —the column of a PAGE row— inside a
              modal, which is the same oversight `MRow` had. */}
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
                value={user}
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
`showClusterOptionsModal` / `saveClusterOptions` (cluster.js:786-928). The four
intervals can only be TOUCHED from the primary node; from a secondary the modal
comes out read-only and with no save button. The cluster's domain is always
locked: it can never be changed.
*/
function OpcionesCluster({
  token,
  node,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  onCerrar: () => void
  onHecho: () => void
}) {
  const [loading, setLoading] = useState(true)
  const [esPrimario, setEsPrimario] = useState(false)
  const [dominio, setDominio] = useState('')
  const [hbRefresh, setHbRefresh] = useState('')
  const [hbRetry, setHbRetry] = useState('')
  const [cfgRefresh, setCfgRefresh] = useState('')
  const [cfgRetry, setCfgRetry] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: node }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
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
  }, [token, node])

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

    setBusy(true)
    const outcome = await setClusterOptions(
      token,
      {
        heartbeatRefreshIntervalSeconds: hbRefresh,
        heartbeatRetryIntervalSeconds: hbRetry,
        configRefreshIntervalSeconds: cfgRefresh,
        configRetryIntervalSeconds: cfgRetry,
      },
      node,
    )
    setBusy(false)

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
      size="medium"
      actions={
        <>
          {esPrimario && (
            <Button variant="primary" disabled={busy || loading} onClick={() => void guardar()}>
              Save
            </Button>
          )}
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      {loading ? (
        <Loading />
      ) : (
        <>
          <MRow label="Cluster Domain" help="The fully qualified domain name of the Cluster.">
            {(id) => <Input id={id} placeholder="domain name" value={dominio} disabled readOnly />}
          </MRow>
          {intervalos.map(([label, value, sufijo, set, help]) => (
            <MRow key={label} label={label} help={help}>
              {(id) => (
                <div className={styles.ctlLine}>
                  <Input
                    id={id}
                    type="number"
                    placeholder="seconds"
                    style={{ width: 100 }}
                    disabled={!esPrimario}
                    value={value}
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
  node,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [list, setLista] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: node, includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setAviso(avisoDeFallo(outcome))
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token, node])

  async function guardar() {
    const limpia = limpiarLista(list)
    if (limpia.length === 0 || limpia === ',') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a node IP address.' })
      return
    }

    setBusy(true)
    const outcome = await updateIpAddress(token, limpia, node)
    setBusy(false)

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
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      {loading ? (
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
                value={list}
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
 *  It loads nothing: it comes up with whatever was already in the row. */
function EditarNodoPrimario({
  token,
  node,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [url, setUrl] = useState(objetivo.url)
  const [list, setLista] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  async function guardar() {
    if (url === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Primary node URL.' })
      return
    }
    // Here the list CAN be left empty: it is optional. Upstream only normalises
    // the degenerate case of a stray comma (cluster.js:400).
    let limpia = limpiarLista(list)
    if (limpia === ',') limpia = ''

    setBusy(true)
    const outcome = await updatePrimaryNode(token, url, limpia, node)
    setBusy(false)

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
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
            value={list}
            onChange={(e) => setLista(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/** `showRemoveSecondaryClusterNodeModal` / `removeSecondaryClusterNode`
 *  (cluster.js:434-495). The checkbox changes the ENDPOINT, not a parameter. */
function QuitarNodo({
  token,
  node,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  async function quitar() {
    setBusy(true)
    const id = String(objetivo.id)
    const outcome = forzar
      ? await deleteSecondaryNode(token, id, node)
      : await removeSecondaryNode(token, id, node)
    setBusy(false)

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
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void quitar()}>
            Remove
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
  node,
  objetivo,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  async function promocionar() {
    setBusy(true)
    const outcome = await promoteToPrimary(token, forzar, node)
    setBusy(false)

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
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void promocionar()}>
            Promote
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
  node,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  async function salir() {
    setBusy(true)
    const outcome = await leaveCluster(token, forzar, node)
    setBusy(false)

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
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void salir()}>
            Leave
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
  node,
  onCerrar,
  onHecho,
}: {
  token: string | null
  node: string
  onCerrar: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [forzar, setForzar] = useState(false)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  async function borrar() {
    setBusy(true)
    const outcome = await deleteCluster(token, forzar, node)
    setBusy(false)

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
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void borrar()}>
            Delete
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
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
