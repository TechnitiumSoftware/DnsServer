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
import { Confirmar } from '../../ui/Confirmar'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { errorAviso, type Aviso } from './avisos'
import { formularioDesdeScope, formularioNuevo, type ScopeForm as Form } from './model'
import { ScopeForm } from './ScopeForm'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { avisoDeFallo } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'

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
  /** `DhcpServer.canModify`: guardar, habilitar y deshabilitar. */
  canModify?: boolean
  /** `DhcpServer.canDelete`: borrar un scope. */
  canDelete?: boolean
}

type Editing = { titulo: 'Add Scope' | 'Edit Scope'; form: Form }

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
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [confirmar, setConfirmar] = useState<{ action: 'disable' | 'delete'; name: string } | null>(
    null,
  )

  // A failure on load is not drawn as an empty list; see `Leases`.
  const cargar = useCallback(async () => {
    setScopes(null)
    const r = await listScopes(token, node)
    if (r.kind === 'ok') {
      setScopes(r.data)
      return
    }
    setScopes([])
    setAviso(avisoDeFallo(r))
  }, [token, node])

  useEffect(() => {
    void cargar()
  }, [cargar])

  // The hook goes BEFORE any return: otherwise it would stop being called as soon
  // as the table is loading.
  const { rows: scopesVisibles, orden, alternar } = useOrden(KEYS, scopes ?? [])

  async function editar(name: string) {
    setBusy(true)
    const s = await getScope(token, name, node)
    setBusy(false)
    if (s == null) return
    setEditing({ titulo: 'Edit Scope', form: formularioDesdeScope(s) })
  }

  async function guardar(body: Record<string, string>) {
    setBusy(true)
    const outcome = await setScope(token, body, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(errorAviso(outcome))
      return
    }

    setEditing(null)
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Saved!',
      text: 'DHCP Scope was saved successfully.',
    })
  }

  async function habilitar(name: string) {
    setBusy(true)
    const outcome = await enableScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Enabled!',
      text: 'DHCP Scope was enabled successfully.',
    })
  }

  async function deshabilitar(name: string) {
    setConfirmar(null)
    setBusy(true)
    const outcome = await disableScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Disabled!',
      text: 'DHCP Scope was disabled successfully.',
    })
  }

  async function borrar(name: string) {
    setConfirmar(null)
    setBusy(true)
    const outcome = await deleteScope(token, name, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return
    // dhcp.js:662 — it removes the row; it does not ask for the list again.
    setScopes((prev) => prev?.filter((s) => s.name !== name) ?? prev)
    setAviso({
      type: 'success',
      title: 'Scope Deleted!',
      text: 'DHCP Scope was deleted successfully.',
    })
  }

  if (editing != null) {
    return (
      <div className={styles.wrap}>
        <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
        <ScopeForm
          key={editing.titulo + editing.form.oldName}
          titulo={editing.titulo}
          inicial={editing.form}
          busy={busy}
          onGuardar={(body) => void guardar(body)}
          onCancelar={() => {
            setEditing(null)
            void cargar()
          }}
          onAviso={(e) => setAviso({ type: 'warning', title: e.title, text: e.text })}
        />
      </div>
    )
  }

  if (scopes == null) return <Loading />

  return (
    <div className={styles.wrap}>
      <SectionHeader
        section="DHCP"
        titulo="Scopes"
        actions={<>{canModify && (
            <Button
              variant="primary"
              onClick={() => {
                setAviso(null)
                setEditing({ titulo: 'Add Scope', form: formularioNuevo() })
              }}
            >
              Add Scope
            </Button>
          )}</>}
      />

      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      <Table
        header={
          <>
            <Th field="name" orden={orden} onOrdenar={alternar}>Name</Th>
            <Th field="range" orden={orden} onOrdenar={alternar}>Scope Range/Subnet Mask</Th>
            <Th field="network" orden={orden} onOrdenar={alternar}>Network/Broadcast</Th>
            <Th field="interfaz" orden={orden} onOrdenar={alternar}>Interface</Th>
            <th>Status</th>
            <th className={tbl.celdaAcciones} />
          </>
        }
        isEmpty={scopesVisibles.length === 0}
        emptyText="No Scope Found"
        columnas={6}
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
            <td className={tbl.celdaAcciones}>
              <div className={tbl.actions}>
                <AccionFila
                  icono="editar"
                  name="Edit Scope"
                  disabled={busy}
                  onClick={() => void editar(s.name)}
                />
                {canModify && (
                  /* dhcp.js:615 — enabling asks nothing; disabling does. */
                  <AccionFila
                    icono="energia"
                    name={s.enabled ? 'Disable Scope' : 'Enable Scope'}
                    disabled={busy}
                    onClick={() =>
                      s.enabled
                        ? setConfirmar({ action: 'disable', name: s.name })
                        : void habilitar(s.name)
                    }
                  />
                )}
                {canDelete && (
                  <Menu etiqueta={`Actions for ${s.name}`}>
                    {(cerrar) => (
                      <button
                        type="button"
                        data-variant="danger"
                        disabled={busy}
                        onClick={() => { cerrar(); setConfirmar({ action: 'delete', name: s.name }) }}
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

      <Confirmar
        abierto={confirmar !== null}
        titulo={confirmar?.action === 'delete' ? 'Delete Scope' : 'Disable Scope'}
        text={
          confirmar?.action === 'delete'
            ? `Are you sure you want to delete the DHCP scope '${confirmar.name}'?`
            : `Are you sure you want to disable the DHCP scope '${confirmar?.name ?? ''}'?`
        }
        etiqueta={confirmar?.action === 'delete' ? 'Delete' : 'Disable'}
        busy={busy}
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => {
          if (!confirmar) return
          if (confirmar.action === 'delete') void borrar(confirmar.name)
          else void deshabilitar(confirmar.name)
        }}
      />
    </div>
  )
}
