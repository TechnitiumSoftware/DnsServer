import { useCallback, useEffect, useId, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select, Textarea } from '../../ui/Field'
import { Radios } from '../../ui/PanelForm'
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
import { cleanList } from '../settings/model'
import { fromNow, fechaMinuto } from './dates'
import {
  noticeFromFailure,
  Check,
  Confirm,
  MRow,
  NodePicker,
  adminStyles as styles,
  type Notice,
} from './parts'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu, Separador } from '../../ui/Menu'
import { GroupRow } from '../../ui/Form'
import { Notifier } from '../../ui/Notifier'

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
  onNotice: (a: Notice) => void
}

type Modal =
  | { type: 'new' }
  | { type: 'join' }
  | { type: 'options' }
  | { type: 'editSelf'; node: ClusterNode }
  | { type: 'editPrimary'; node: ClusterNode }
  | { type: 'remove'; node: ClusterNode }
  | { type: 'promote'; node: ClusterNode }
  | { type: 'leave' }
  | { type: 'delete' }
  | { type: 'resync' }

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

export function Cluster({ token, cluster, onCluster, onNotice }: Props) {
  const [node, setNode] = useState('')
  const [state, setEstado] = useState<ClusterState | null>(cluster)
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState<Modal | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await getClusterState(token, { node: node })
    setLoading(false)

    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    setEstado(outcome.data.response)
    onCluster(outcome.data.response)
  }, [token, node, onCluster, onNotice])

  useEffect(() => {
    void load()
  }, [load])


  function reloadWith(s: ClusterState) {
    setEstado(s)
    onCluster(s)
  }

  const nodes = state?.clusterNodes ?? []
  const { rows: visibleNodes, sort, toggle } = useOrden(KEYS, nodes)
  const ownType = nodes.find((n) => n.state === 'Self')?.type
  const initialised = state?.clusterInitialized === true
  const esPrimario = ownType === 'Primary'

  async function lanzarResync() {
    setModal(null)
    const outcome = await resyncCluster(token, node)
    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    onNotice({
      type: 'success',
      title: 'Resync Triggered!',
      text: 'A full config resync was triggered successfully. Please check the Logs for confirmation.',
    })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        title="Cluster"
        actions={<>{initialised && !esPrimario && (
            <Button variant="primary" onClick={() => setModal({ type: 'resync' })}>
              Resync
            </Button>
          )}
          {initialised && (
            <Button variant="primary" onClick={() => setModal({ type: 'options' })}>
              Options
            </Button>
          )}
          {initialised && !esPrimario && (
            <Button onClick={() => setModal({ type: 'leave' })}>Leave Cluster</Button>
          )}
          {initialised && esPrimario && (
            <Button variant="danger" onClick={() => setModal({ type: 'delete' })}>
              Delete Cluster
            </Button>
          )}
          <NodePicker cluster={state} value={node} onChange={setNode} label="Cluster Node" /></>}
      />

      {loading ? (
        <Loading />
      ) : !initialised ? (
        <Empty
          title="Cluster Not Initialized"
          actions={
            <>
              <Button variant="primary" onClick={() => setModal({ type: 'new' })}>
                New Cluster
              </Button>
              <Button onClick={() => setModal({ type: 'join' })}>Join Cluster</Button>
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
                <Th field="name" sort={sort} onSort={toggle}>Node Name</Th>
                <Th field="ip" sort={sort} onSort={toggle}>IP Address</Th>
                <Th field="url" sort={sort} onSort={toggle}>URL</Th>
                <Th field="type" sort={sort} onSort={toggle}>Type</Th>
                <Th field="state" sort={sort} onSort={toggle}>State</Th>
                <Th field="upSince" sort={sort} onSort={toggle}>Up Since</Th>
                <Th field="lastSeen" sort={sort} onSort={toggle}>Last Seen</Th>
                <Th field="synced" sort={sort} onSort={toggle}>Last Synced</Th>
                <th className={tbl.actionsCell} />
              </>
            }
            isEmpty={visibleNodes.length === 0}
            emptyText="No Node Found"
            columns={9}
          >
            {visibleNodes.map((n) => (
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
                <td className={tbl.actionsCell}>
                  <div className={tbl.actions}>
                    {/* What can be done with a node depends on whether this
                        console is talking to the primary or to a secondary
                        (cluster.js:248-264). Editing is the frequent one and goes
                        in the row; removing and promoting, inside the menu. */}
                    {(esPrimario ? n.state === 'Self' : n.state === 'Self' || n.type === 'Primary') && (
                      <RowAction
                        icon="edit"
                        name="Edit Node"
                        onClick={() =>
                          setModal({
                            type: n.state === 'Self' ? 'editSelf' : 'editPrimary',
                            node: n,
                          })
                        }
                      />
                    )}
                    {((esPrimario && n.type === 'Secondary') ||
                      (ownType === 'Secondary' && n.state === 'Self')) && (
                      <Menu label={`Actions for ${n.name}`}>
                        {(close) => (
                          <>
                            {ownType === 'Secondary' && n.state === 'Self' && (
                              <button type="button" onClick={() => { close(); setModal({ type: 'promote', node: n }) }}>
                                Promote To Primary
                              </button>
                            )}
                            {esPrimario && n.type === 'Secondary' && (
                              <>
                                <Separador />
                                <button type="button" data-variant="danger" onClick={() => { close(); setModal({ type: 'remove', node: n }) }}>
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

      <Confirm
        open={modal?.type === 'resync'}
        title="Resync Cluster"
        text={
          <>
            The resync Cluster action will initiate a full config transfer from the Primary node.
            You will need to check the logs to confirm if the resync action was successful.
            <br />
            <br />
            Are you sure you want to resync the Cluster config?
          </>
        }
        label="Resync"
        variante="primary"
        onClose={() => setModal(null)}
        onConfirm={() => void lanzarResync()}
      />

      {modal?.type === 'new' && (
        <NewCluster
          token={token}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Cluster Initialized!',
              text: 'A new cluster was initialized successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'join' && (
        <JoinCluster
          token={token}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Joined Cluster!',
              text: 'Joined the cluster successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'options' && (
        <ClusterOptions
          token={token}
          node={node}
          onClose={() => setModal(null)}
          onHecho={() => {
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Options Saved!',
              text: 'The Cluster options were saved successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'editSelf' && (
        <EditOwnNode
          token={token}
          node={node}
          objetivo={modal.node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Node Updated!',
              text: 'Cluster node was updated successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'editPrimary' && (
        <EditPrimaryNode
          token={token}
          node={node}
          objetivo={modal.node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Node Updated!',
              text: 'Cluster node was updated successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'remove' && (
        <RemoveNode
          token={token}
          node={node}
          objetivo={modal.node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Node Removed!',
              text: 'Cluster node was removed successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'promote' && (
        <PromoteNode
          token={token}
          node={node}
          objetivo={modal.node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Promoted!',
              text: 'The selected node was successfully promoted to Primary node in the Cluster.',
            })
          }}
        />
      )}

      {modal?.type === 'leave' && (
        <LeaveCluster
          token={token}
          node={node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
              type: 'success',
              title: 'Left Cluster!',
              text: 'Left the Cluster successfully.',
            })
          }}
        />
      )}

      {modal?.type === 'delete' && (
        <DeleteCluster
          token={token}
          node={node}
          onClose={() => setModal(null)}
          onHecho={(s) => {
            reloadWith(s)
            setModal(null)
            onNotice({
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
      <div className={styles.meta}>{`(${fromNow(iso)})`}</div>
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
  onAdd,
  label,
}: {
  ips: string[]
  onAdd: (ip: string) => void
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
          if (e.target.value !== '') onAdd(e.target.value)
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

function addIp(list: string, ip: string): string {
  return list.indexOf(ip) < 0 ? `${list}${ip}\n` : list
}

/** `showInitializeClusterModal` / `initializeNewCluster` (cluster.js:548-645). */
function NewCluster({
  token,
  onClose,
  onHecho,
}: {
  token: string | null
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [domain, setDomain] = useState('')
  const [list, setList] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setNotice(noticeFromFailure(outcome))
        return
      }
      if (outcome.data.response.clusterInitialized) {
        setYaEsta(true)
        setNotice({ type: 'danger', title: 'Error!', text: 'Cluster is already initialized.' })
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token])

  async function inicializar() {
    if (domain === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter the Cluster domain name.' })
      return
    }
    const limpia = cleanList(list)
    if (limpia.length === 0 || limpia === ',') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a Primary node IP address.',
      })
      return
    }

    setBusy(true)
    const outcome = await initCluster(token, domain, limpia)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
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
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
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
                  onChange={(e) => setList(e.target.value)}
                />
                <QuickAdd
                  ips={ips}
                  label="Quick Add"
                  onAdd={(ip) => setList((t) => addIp(t, ip))}
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
          <div className={styles.link}>
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
function JoinCluster({
  token,
  onClose,
  onHecho,
}: {
  token: string | null
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [yaEsta, setYaEsta] = useState(false)
  const [list, setList] = useState('')
  const [url, setUrl] = useState('')
  const [ip, setIp] = useState('')
  const [ignorar, setIgnorar] = useState('false')
  const [user, setUser] = useState('admin')
  const [pass, setPass] = useState('')
  const [totp, setTotp] = useState('')
  const [pideTotp, setPideTotp] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setNotice(noticeFromFailure(outcome))
        return
      }
      if (outcome.data.response.clusterInitialized) {
        setYaEsta(true)
        setNotice({ type: 'danger', title: 'Error!', text: 'Cluster is already initialized.' })
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token])

  async function join() {
    const limpia = cleanList(list)
    if (limpia.length === 0 || limpia === ',') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please select a Secondary node IP address.',
      })
      return
    }
    if (url === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter the Primary node URL.' })
      return
    }
    if (user === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the Primary node admin username.',
      })
      return
    }
    if (pass === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter the Primary node admin password.',
      })
      return
    }
    // The OTP is only required when the field is in sight, and it is only put in
    // sight after the server answers `2fa-required`.
    if (pideTotp && totp === '') {
      setNotice({
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
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Join Cluster"
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading || yaEsta} onClick={() => void join()}>
            Join
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
                  onChange={(e) => setList(e.target.value)}
                />
                <QuickAdd
                  ips={ips}
                  label="Quick Add"
                  onAdd={(v) => setList((t) => addIp(t, v))}
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
                onChange={(e) => setUser(e.target.value)}
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
          <div className={styles.link}>
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
function ClusterOptions({
  token,
  node,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  onClose: () => void
  onHecho: () => void
}) {
  const [loading, setLoading] = useState(true)
  const [esPrimario, setEsPrimario] = useState(false)
  const [domain, setDomain] = useState('')
  const [hbRefresh, setHbRefresh] = useState('')
  const [hbRetry, setHbRetry] = useState('')
  const [cfgRefresh, setCfgRefresh] = useState('')
  const [cfgRetry, setCfgRetry] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: node }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setNotice(noticeFromFailure(outcome))
        return
      }
      const r = outcome.data.response
      setEsPrimario(r.clusterNodes?.find((n) => n.state === 'Self')?.type === 'Primary')
      setDomain(r.clusterDomain ?? '')
      setHbRefresh(String(r.heartbeatRefreshIntervalSeconds ?? ''))
      setHbRetry(String(r.heartbeatRetryIntervalSeconds ?? ''))
      setCfgRefresh(String(r.configRefreshIntervalSeconds ?? ''))
      setCfgRetry(String(r.configRetryIntervalSeconds ?? ''))
    })
    return () => {
      vivo = false
    }
  }, [token, node])

  async function save() {
    if (hbRefresh === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Heartbeat Refresh Interval.',
      })
      return
    }
    if (hbRetry === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Heartbeat Retry Interval.',
      })
      return
    }
    if (cfgRefresh === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value for Config Refresh Interval.',
      })
      return
    }
    if (cfgRetry === '') {
      setNotice({
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
      setNotice(noticeFromFailure(outcome))
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
      onOpenChange={(o) => !o && onClose()}
      title="Cluster Options"
      size="medium"
      actions={
        <>
          {esPrimario && (
            <Button variant="primary" disabled={busy || loading} onClick={() => void save()}>
              Save
            </Button>
          )}
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      {loading ? (
        <Loading />
      ) : (
        <>
          <MRow label="Cluster Domain" help="The fully qualified domain name of the Cluster.">
            {(id) => <Input id={id} placeholder="domain name" value={domain} disabled readOnly />}
          </MRow>
          {intervalos.map(([label, value, suffix, set, help]) => (
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
                  <span className={styles.suffix}>{suffix}</span>
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
function EditOwnNode({
  token,
  node,
  objetivo,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [loading, setLoading] = useState(true)
  const [ips, setIps] = useState<string[]>([])
  const [list, setList] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let vivo = true
    void getClusterState(token, { node: node, includeServerIpAddresses: true }).then((outcome) => {
      if (!vivo) return
      setLoading(false)
      if (outcome.kind !== 'ok') {
        setNotice(noticeFromFailure(outcome))
        return
      }
      setIps(outcome.data.response.serverIpAddresses ?? [])
    })
    return () => {
      vivo = false
    }
  }, [token, node])

  async function save() {
    const limpia = cleanList(list)
    if (limpia.length === 0 || limpia === ',') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter a node IP address.' })
      return
    }

    setBusy(true)
    const outcome = await updateIpAddress(token, limpia, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Edit Node - ${objetivo.name}`}
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
                onChange={(e) => setList(e.target.value)}
              />
              <QuickAdd ips={ips} label="Quick Add" onAdd={(ip) => setList((t) => addIp(t, ip))} />
            </>
          )}
        </MRow>
      )}
    </Dialog>
  )
}

/** `showEditPrimaryClusterNodeModal` / `updatePrimaryClusterNode` (cluster.js:363-432).
 *  It loads nothing: it comes up with whatever was already in the row. */
function EditPrimaryNode({
  token,
  node,
  objetivo,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [url, setUrl] = useState(objetivo.url)
  const [list, setList] = useState(`${objetivo.ipAddresses.join('\n')}\n`)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function save() {
    if (url === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter the Primary node URL.' })
      return
    }
    // Here the list CAN be left empty: it is optional. Upstream only normalises
    // the degenerate case of a stray comma (cluster.js:400).
    let limpia = cleanList(list)
    if (limpia === ',') limpia = ''

    setBusy(true)
    const outcome = await updatePrimaryNode(token, url, limpia, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Edit Node - ${objetivo.name}`}
      size="medium"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
            onChange={(e) => setList(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/** `showRemoveSecondaryClusterNodeModal` / `removeSecondaryClusterNode`
 *  (cluster.js:434-495). The checkbox changes the ENDPOINT, not a parameter. */
function RemoveNode({
  token,
  node,
  objetivo,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [force, setForce] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function discard() {
    setBusy(true)
    const id = String(objetivo.id)
    const outcome = force
      ? await deleteSecondaryNode(token, id, node)
      : await removeSecondaryNode(token, id, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Remove Node - ${objetivo.name}`}
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void discard()}>
            Remove
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <p className={styles.parrafo}>
        The Remove Node process will ask the selected Secondary node to leave the Cluster gracefully.
        The Secondary will then initiate Leave Cluster process as if the Leave Cluster action was
        performed on that node itself.
      </p>
      <Check
        toggle
        label="Force Remove Node"
        checked={force}
        onChange={setForce}
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
function PromoteNode({
  token,
  node,
  objetivo,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  objetivo: ClusterNode
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [force, setForce] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function promocionar() {
    setBusy(true)
    const outcome = await promoteToPrimary(token, force, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Promote To Primary Node - ${objetivo.name}`}
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void promocionar()}>
            Promote
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <p className={styles.parrafo}>
        The promote To Primary node process will resync complete configuration from the Primary node
        and then proceed to delete it from the Cluster followed by upgrading the selected Secondary
        node to become the Primary node in the Cluster. The former Primary node when deleted will
        cause it to delete all its own Cluster configuration leaving the Cluster without causing any
        other data loss.
      </p>
      <Check
        toggle
        label="Force Delete Current Primary Node"
        checked={force}
        onChange={setForce}
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
function LeaveCluster({
  token,
  node,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [force, setForce] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function salir() {
    setBusy(true)
    const outcome = await leaveCluster(token, force, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Leave Cluster"
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void salir()}>
            Leave
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <p className={styles.parrafo}>
        The Leave Cluster process will remove all Cluster configuration from this Secondary node and
        leave the Cluster gracefully. There will be no data loss except for the Cluster
        configuration. You will need to re-join the Cluster again to use this DNS Server as a
        Secondary node.
      </p>
      <Check
        toggle
        label="Force Leave Cluster"
        checked={force}
        onChange={setForce}
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
function DeleteCluster({
  token,
  node,
  onClose,
  onHecho,
}: {
  token: string | null
  node: string
  onClose: () => void
  onHecho: (s: ClusterState) => void
}) {
  const [force, setForce] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function remove() {
    setBusy(true)
    const outcome = await deleteCluster(token, force, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onHecho(outcome.data.response)
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Delete Cluster"
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void remove()}>
            Delete
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <p className={styles.parrafo}>
        The Delete Cluster process will remove all Cluster configuration from this Primary node.
        There will be no data loss except for the Cluster configuration. You will need to
        re-initialize the Cluster again to use clustering features on this DNS Server.
      </p>
      <Check
        toggle
        label="Force Delete Cluster"
        checked={force}
        onChange={setForce}
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
