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
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { errorAviso, type Aviso } from './avisos'
import { formularioDesdeScope, formularioNuevo, type ScopeForm as Form } from './model'
import { ScopeForm } from './ScopeForm'
import styles from './Dhcp.module.css'

/*
DHCP › Scopes (dhcp.js:201-684).

Cuatro asimetrías de upstream que parecen descuidos y no lo son, y que se
replican tal cual:

  1. **Habilitar un scope NO pide confirmación; deshabilitarlo, sí**
     (dhcp.js:583 vs 615). Sólo el camino que corta el servicio pregunta.
  2. **Borrar tampoco recarga la lista**: quita la fila y recalcula el pie
     (dhcp.js:662-668). Habilitar, deshabilitar y guardar sí recargan.
  3. **El formulario sustituye a la tabla**, no se abre en un modal.
  4. **El permiso de borrar un scope es `Delete`, no `Modify`**
     (`WebServiceDhcpApi.cs:761`), mientras que habilitar y deshabilitar son
     `Modify`. Guardar es `Modify`.
*/

export interface ScopesProps {
  token: string | null
  node?: string
  /** `DhcpServer.canModify`: guardar, habilitar y deshabilitar. */
  canModify?: boolean
  /** `DhcpServer.canDelete`: borrar un scope. */
  canDelete?: boolean
}

type Edicion = { titulo: 'Add Scope' | 'Edit Scope'; form: Form }

export function Scopes({ token, node = '', canModify = true, canDelete = true }: ScopesProps) {
  const [scopes, setScopes] = useState<DhcpScopeRow[] | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [edicion, setEdicion] = useState<Edicion | null>(null)
  const [confirmar, setConfirmar] = useState<{ accion: 'disable' | 'delete'; nombre: string } | null>(
    null,
  )

  const cargar = useCallback(async () => {
    setScopes(null)
    setScopes(await listScopes(token, node))
  }, [token, node])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function editar(nombre: string) {
    setOcupado(true)
    const s = await getScope(token, nombre, node)
    setOcupado(false)
    if (s == null) return
    setEdicion({ titulo: 'Edit Scope', form: formularioDesdeScope(s) })
  }

  async function guardar(body: Record<string, string>) {
    setOcupado(true)
    const outcome = await setScope(token, body, node)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(errorAviso(outcome))
      return
    }

    setEdicion(null)
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Saved!',
      text: 'DHCP Scope was saved successfully.',
    })
  }

  async function habilitar(nombre: string) {
    setOcupado(true)
    const outcome = await enableScope(token, nombre, node)
    setOcupado(false)
    if (outcome.kind !== 'ok') return
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Enabled!',
      text: 'DHCP Scope was enabled successfully.',
    })
  }

  async function deshabilitar(nombre: string) {
    setConfirmar(null)
    setOcupado(true)
    const outcome = await disableScope(token, nombre, node)
    setOcupado(false)
    if (outcome.kind !== 'ok') return
    await cargar()
    setAviso({
      type: 'success',
      title: 'Scope Disabled!',
      text: 'DHCP Scope was disabled successfully.',
    })
  }

  async function borrar(nombre: string) {
    setConfirmar(null)
    setOcupado(true)
    const outcome = await deleteScope(token, nombre, node)
    setOcupado(false)
    if (outcome.kind !== 'ok') return
    // dhcp.js:662 — quita la fila; no vuelve a pedir la lista.
    setScopes((prev) => prev?.filter((s) => s.name !== nombre) ?? prev)
    setAviso({
      type: 'success',
      title: 'Scope Deleted!',
      text: 'DHCP Scope was deleted successfully.',
    })
  }

  if (edicion != null) {
    return (
      <div className={styles.wrap}>
        {aviso && (
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        )}
        <ScopeForm
          key={edicion.titulo + edicion.form.oldName}
          titulo={edicion.titulo}
          inicial={edicion.form}
          ocupado={ocupado}
          onGuardar={(body) => void guardar(body)}
          onCancelar={() => {
            setEdicion(null)
            void cargar()
          }}
          onAviso={(e) => setAviso({ type: 'warning', title: e.title, text: e.text })}
        />
      </div>
    )
  }

  if (scopes == null) return <div className={styles.loading}>Loading…</div>

  return (
    <div className={styles.wrap}>
      <div className={styles.hrow}>
        <div>
          <h1 className={styles.zt}>DHCP Scopes</h1>
        </div>
        <div className={styles.acts}>
          {canModify && (
            <Button
              variant="primary"
              onClick={() => {
                setAviso(null)
                setEdicion({ titulo: 'Add Scope', form: formularioNuevo() })
              }}
            >
              Add Scope
            </Button>
          )}
        </div>
      </div>

      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

      <div className={styles.tablaWrap}>
        <table className={styles.tabla}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Scope Range/Subnet Mask</th>
              <th>Network/Broadcast</th>
              <th>Interface</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scopes.map((s) => (
              <tr key={s.name}>
                <td className={styles.nombre}>{s.name}</td>
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
                {/* `interfaceAddress` se OMITE cuando es nulo; upstream pinta
                    una celda vacía (dhcp.js:228). */}
                <td className={styles.mono}>{s.interfaceAddress ?? ''}</td>
                <td>
                  <span className={s.enabled ? `${styles.tag} ${styles.tagOk}` : styles.tag}>
                    {s.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td>
                  <div className={styles.rowacts}>
                    <Button disabled={ocupado} onClick={() => void editar(s.name)}>
                      Edit
                    </Button>
                    {canModify &&
                      (s.enabled ? (
                        <Button
                          disabled={ocupado}
                          onClick={() => setConfirmar({ accion: 'disable', nombre: s.name })}
                        >
                          Disable
                        </Button>
                      ) : (
                        /* dhcp.js:615 — habilitar no pregunta nada. */
                        <Button disabled={ocupado} onClick={() => void habilitar(s.name)}>
                          Enable
                        </Button>
                      ))}
                    {canDelete && (
                      <Button
                        variant="danger"
                        disabled={ocupado}
                        onClick={() => setConfirmar({ accion: 'delete', nombre: s.name })}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className={styles.total}>
        {scopes.length > 0 ? <b>Total Scopes: {scopes.length}</b> : 'No Scope Found'}
      </div>

      <Dialog
        open={confirmar !== null}
        onOpenChange={(o) => !o && setConfirmar(null)}
        title={confirmar?.accion === 'delete' ? 'Delete Scope' : 'Disable Scope'}
        footer={
          <>
            <Button onClick={() => setConfirmar(null)}>Cancel</Button>
            <Button
              variant="danger"
              disabled={ocupado}
              onClick={() => {
                if (!confirmar) return
                if (confirmar.accion === 'delete') void borrar(confirmar.nombre)
                else void deshabilitar(confirmar.nombre)
              }}
            >
              {confirmar?.accion === 'delete' ? 'Delete' : 'Disable'}
            </Button>
          </>
        }
      >
        <p className={styles.parrafo}>
          {confirmar?.accion === 'delete'
            ? `Are you sure you want to delete the DHCP scope '${confirmar.nombre}'?`
            : `Are you sure you want to disable the DHCP scope '${confirmar?.nombre ?? ''}'?`}
        </p>
      </Dialog>
    </div>
  )
}
