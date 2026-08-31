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
import { SectionHeader } from '../../ui/SectionHeader'
import { errorAviso, type Aviso } from './avisos'
import { formularioDesdeScope, formularioNuevo, type ScopeForm as Form } from './model'
import { ScopeForm } from './ScopeForm'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'
import { AccionFila, Th, useOrden, type Claves } from '../../ui/Table'
import { Menu } from '../../ui/Menu'

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

/* `sortTable('tableDhcpScopesBody', 0..3)`. Se ordena por el texto de la celda,
   que en las dos columnas compuestas son sus dos pares rótulo/valor. */
const CLAVES: Claves<DhcpScopeRow> = {
  name: (s) => s.name,
  range: (s) => `Range ${s.startingAddress} - ${s.endingAddress} Mask ${s.subnetMask}`,
  network: (s) => `Network ${s.networkAddress} Broadcast ${s.broadcastAddress}`,
  interfaz: (s) => s.interfaceAddress ?? '',
}

export function Scopes({ token, node = '', canModify = true, canDelete = true }: ScopesProps) {
  const [scopes, setScopes] = useState<DhcpScopeRow[] | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [edicion, setEdicion] = useState<Edicion | null>(null)
  const [confirmar, setConfirmar] = useState<{ accion: 'disable' | 'delete'; nombre: string } | null>(
    null,
  )

  // Un fallo al cargar no se pinta como lista vacía; ver `Leases`.
  const cargar = useCallback(async () => {
    setScopes(null)
    const r = await listScopes(token, node)
    if (r.kind === 'ok') {
      setScopes(r.data)
      return
    }
    setScopes([])
    setAviso({
      type: 'danger',
      title: 'Error!',
      text: r.kind === 'error' ? r.message : 'Invalid token or session expired.',
    })
  }, [token, node])

  useEffect(() => {
    void cargar()
  }, [cargar])

  // El hook va ANTES de cualquier return: si no, dejaría de llamarse en cuanto
  // la tabla está cargando.
  const { filas: scopesVisibles, orden, alternar } = useOrden(CLAVES, scopes ?? [])

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

  if (scopes == null) return <Loading />

  return (
    <div className={styles.wrap}>
      <SectionHeader
        seccion="DHCP"
        titulo="Scopes"
        acciones={<>{canModify && (
            <Button
              variant="primary"
              onClick={() => {
                setAviso(null)
                setEdicion({ titulo: 'Add Scope', form: formularioNuevo() })
              }}
            >
              Add Scope
            </Button>
          )}</>}
      />

      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

      <div className={tbl.wrap}>
        <table className={tbl.tabla}>
          <thead>
            <tr>
              <Th campo="name" orden={orden} onOrdenar={alternar}>Name</Th>
              <Th campo="range" orden={orden} onOrdenar={alternar}>Scope Range/Subnet Mask</Th>
              <Th campo="network" orden={orden} onOrdenar={alternar}>Network/Broadcast</Th>
              <Th campo="interfaz" orden={orden} onOrdenar={alternar}>Interface</Th>
              <th>Status</th>
              <th className={tbl.celdaAcciones} />
            </tr>
          </thead>
          <tbody>
            {scopesVisibles.map((s) => (
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
                  <Tag tone={s.enabled ? 'ok' : 'neutral'}>
                    {s.enabled ? 'Enabled' : 'Disabled'}
                  </Tag>
                </td>
                <td className={tbl.celdaAcciones}>
                  <div className={tbl.acciones}>
                    <AccionFila
                      icono="editar"
                      nombre="Edit Scope"
                      disabled={ocupado}
                      onClick={() => void editar(s.name)}
                    />
                    {canModify && (
                      /* dhcp.js:615 — habilitar no pregunta nada; deshabilitar sí. */
                      <AccionFila
                        icono="energia"
                        nombre={s.enabled ? 'Disable Scope' : 'Enable Scope'}
                        disabled={ocupado}
                        onClick={() =>
                          s.enabled
                            ? setConfirmar({ accion: 'disable', nombre: s.name })
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
                            disabled={ocupado}
                            onClick={() => { cerrar(); setConfirmar({ accion: 'delete', nombre: s.name }) }}
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
          </tbody>
        </table>
      </div>

      <div className={styles.total}>
        {scopes.length > 0 ? (
          <span>{`Total Scopes: ${scopes.length}`}</span>
        ) : aviso?.type === 'danger' ? (
          'Unable to load the scopes.'
        ) : (
          'No Scope Found'
        )}
      </div>

      <Dialog
        open={confirmar !== null}
        onOpenChange={(o) => !o && setConfirmar(null)}
        title={confirmar?.accion === 'delete' ? 'Delete Scope' : 'Disable Scope'}
        acciones={
          <>
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
        cerrar="Cancel"
        tamano="compacto"
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
