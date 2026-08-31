import { useCallback, useEffect, useState } from 'react'
import {
  deleteScope,
  disableScope,
  enableScope,
  getScope,
  listScopes,
  setScope,
  type DhcpScopeRow,
} from '../../api/dhcp'
import { Confirm } from '../../ui/Confirm'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { errorNotice, type Notice } from './notices'
import { formularioDesdeScope, formularioNuevo, type ScopeForm as Form } from './model'
import { ScopeForm } from './ScopeForm'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { noticeFromFailure } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

/*
DHCP › Scopes (dhcp.js:201-684).

Four asymmetries of upstream's that look like oversights and are not, and that
are replicated as they are:

  1. **Enabling a scope does NOT ask for confirmation; disabling it does**
     (dhcp.js:583 vs 615). Only the path that cuts the service asks.
  2. **Deleting does not reload the list either**: it removes the row and
     recalculates the footer (dhcp.js:662-668). Enable, disable and save do
     reload.
  3. **The form replaces the table**, it does not open in a modal.
  4. **The permission to delete a scope is `Delete`, not `Modify`**
     (`WebServiceDhcpApi.cs:761`), while enabling and disabling are `Modify`.
     Saving is `Modify`.
*/

export interface ScopesProps {
  token: string | null
  node?: string
  /** `DhcpServer.canModify`: save, enable and disable. */
  canModify?: boolean
  /** `DhcpServer.canDelete`: deleting a scope. */
  canDelete?: boolean
}

type Editing = { title: 'Add Scope' | 'Edit Scope'; form: Form }

/* `sortTable('tableDhcpScopesBody', 0..3)`. It sorts by the cell's text, which
   in the two composite columns is their two label/value pairs. */
const KEYS: Keys<DhcpScopeRow> = {
  name: (s) => s.name,
  range: (s) => `Range ${s.startingAddress} - ${s.endingAddress} Mask ${s.subnetMask}`,
  network: (s) => `Network ${s.networkAddress} Broadcast ${s.broadcastAddress}`,
  interfaz: (s) => s.interfaceAddress ?? '',
}

export function Scopes({ token, node = '', canModify = true, canDelete = true }: ScopesProps) {
  const [scopes, setScopes] = useState<DhcpScopeRow[] | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [confirm, setConfirm] = useState<{ action: 'disable' | 'delete'; name: string } | null>(
    null,
  )

  // A failure on load is not drawn as an empty list; see `Leases`.
  const load = useCallback(async () => {
    setScopes(null)
    const r = await listScopes(token, node)
    if (r.kind === 'ok') {
      setScopes(r.data)
      return
    }
    setScopes([])
    setNotice(noticeFromFailure(r))
  }, [token, node])

  useEffect(() => {
    void load()
  }, [load])

  // The hook goes BEFORE any return: otherwise it would stop being called as soon
  // as the table is loading.
  const { rows: scopesVisibles, sort, toggle } = useOrden(KEYS, scopes ?? [])

  async function edit(name: string) {
    setBusy(true)
    const s = await getScope(token, name, node)
    setBusy(false)
    if (s == null) return
    setEditing({ title: 'Edit Scope', form: formularioDesdeScope(s) })
  }

  async function save(body: Record<string, string>) {
    setBusy(true)
    const outcome = await setScope(token, body, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(errorNotice(outcome))
      return
    }

    setEditing(null)
    await load()
    setNotice({
      type: 'success',
      title: 'Scope Saved!',
      text: 'DHCP Scope was saved successfully.',
    })
  }

  async function enable(name: string) {
    setBusy(true)
    const outcome = await enableScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    await load()
    setNotice({
      type: 'success',
      title: 'Scope Enabled!',
      text: 'DHCP Scope was enabled successfully.',
    })
  }

  async function disable(name: string) {
    setConfirm(null)
    setBusy(true)
    const outcome = await disableScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    await load()
    setNotice({
      type: 'success',
      title: 'Scope Disabled!',
      text: 'DHCP Scope was disabled successfully.',
    })
  }

  async function remove(name: string) {
    setConfirm(null)
    setBusy(true)
    const outcome = await deleteScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    // dhcp.js:662 — it removes the row; it does not ask for the list again.
    setScopes((prev) => prev?.filter((s) => s.name !== name) ?? prev)
    setNotice({
      type: 'success',
      title: 'Scope Deleted!',
      text: 'DHCP Scope was deleted successfully.',
    })
  }

  if (editing != null) {
    return (
      <div className={styles.wrap}>
        <Notifier notice={notice} onClose={() => setNotice(null)} />
        <ScopeForm
          key={editing.title + editing.form.oldName}
          title={editing.title}
          initial={editing.form}
          busy={busy}
          onSave={(body) => void save(body)}
          onCancelar={() => {
            setEditing(null)
            void load()
          }}
          onNotice={(e) => setNotice({ type: 'warning', title: e.title, text: e.text })}
        />
      </div>
    )
  }

  if (scopes == null) return <Loading />

  return (
    <div className={styles.wrap}>
      <SectionHeader
        section="DHCP"
        title="Scopes"
        actions={<>{canModify && (
            <Button
              variant="primary"
              onClick={() => {
                setNotice(null)
                setEditing({ title: 'Add Scope', form: formularioNuevo() })
              }}
            >
              Add Scope
            </Button>
          )}</>}
      />

      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <Table
        header={
          <>
            <Th field="name" sort={sort} onSort={toggle}>Name</Th>
            <Th field="range" sort={sort} onSort={toggle}>Scope Range/Subnet Mask</Th>
            <Th field="network" sort={sort} onSort={toggle}>Network/Broadcast</Th>
            <Th field="interfaz" sort={sort} onSort={toggle}>Interface</Th>
            <th>Status</th>
            <th className={tbl.actionsCell} />
          </>
        }
        isEmpty={scopesVisibles.length === 0}
        emptyText="No Scope Found"
        columns={6}
      >
        {scopesVisibles.map((s) => (
          <tr key={s.name}>
            <td className={styles.name}>{s.name}</td>
            <td>
              <dl className={styles.kv}>
                <dt>Range</dt>
                <dd>
                  {s.startingAddress} - {s.endingAddress}
                </dd>
                <dt>Mask</dt>
                <dd>{s.subnetMask}</dd>
              </dl>
            </td>
            <td>
              <dl className={styles.kv}>
                <dt>Network</dt>
                <dd>{s.networkAddress}</dd>
                <dt>Broadcast</dt>
                <dd>{s.broadcastAddress}</dd>
              </dl>
            </td>
            {/* `interfaceAddress` is OMITTED when null; upstream draws an
                empty cell (dhcp.js:228). */}
            <td className={styles.mono}>{s.interfaceAddress ?? ''}</td>
            <td>
              <Tag tone={s.enabled ? 'ok' : 'neutral'}>
                {s.enabled ? 'Enabled' : 'Disabled'}
              </Tag>
            </td>
            <td className={tbl.actionsCell}>
              <div className={tbl.actions}>
                <RowAction
                  icon="edit"
                  name="Edit Scope"
                  disabled={busy}
                  onClick={() => void edit(s.name)}
                />
                {canModify && (
                  /* dhcp.js:615 — enabling asks nothing; disabling does. */
                  <RowAction
                    icon="power"
                    name={s.enabled ? 'Disable Scope' : 'Enable Scope'}
                    disabled={busy}
                    onClick={() =>
                      s.enabled
                        ? setConfirm({ action: 'disable', name: s.name })
                        : void enable(s.name)
                    }
                  />
                )}
                {canDelete && (
                  <Menu label={`Actions for ${s.name}`}>
                    {(close) => (
                      <button
                        type="button"
                        data-variant="danger"
                        disabled={busy}
                        onClick={() => { close(); setConfirm({ action: 'delete', name: s.name }) }}
                      >
                        Delete Scope
                      </button>
                    )}
                  </Menu>
                )}
              </div>
            </td>
          </tr>
        ))}
      </Table>

      <div className={styles.total}>
        {/* The footer is the count and nothing else. When there are no rows,
            the one that says so is the table itself —with its centred row, like
            the rest of the console and like upstream (`dhcp.js:74`)—; here it was
            left floating outside the panel, under a table with a blank body. */}
        <span>{`Total Scopes: ${scopes.length}`}</span>
      </div>

      <Confirm
        open={confirm !== null}
        title={confirm?.action === 'delete' ? 'Delete Scope' : 'Disable Scope'}
        text={
          confirm?.action === 'delete'
            ? `Are you sure you want to delete the DHCP scope '${confirm.name}'?`
            : `Are you sure you want to disable the DHCP scope '${confirm?.name ?? ''}'?`
        }
        label={confirm?.action === 'delete' ? 'Delete' : 'Disable'}
        busy={busy}
        onClose={() => setConfirm(null)}
        onConfirm={() => {
          if (!confirm) return
          if (confirm.action === 'delete') void remove(confirm.name)
          else void disable(confirm.name)
        }}
      />
    </div>
  )
}
