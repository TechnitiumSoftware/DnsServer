import { useCallback, useEffect, useState } from 'react'
import {
  convertToDynamicLease,
  convertToReservedLease,
  listLeases,
  removeLease,
  type DhcpLease,
} from '../../api/dhcp'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import { fechaMinuto } from './fechas'
import type { Aviso } from './avisos'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'

/*
DHCP › Leases (dhcp.js:37-199).

Tres detalles de upstream que no se ven en el dibujo y que aquí se conservan:

  1. **La tabla NO se recarga tras una acción.** Convertir una concesión cambia
     la etiqueta de tipo de esa fila y las dos opciones de su menú; quitarla
     borra la fila y recalcula el pie. En ningún caso se vuelve a pedir la lista.
  2. **El aviso de «Remove Lease» sale DENTRO del modal cuando falla** y en la
     pantalla cuando sale bien: upstream le pasa a `showAlert` el
     `divDhcpRemoveLeaseAlert` del propio modal sólo en la rama de error.
  3. **Las dos conversiones se confirman con un `confirm()`** y el borrado con un
     modal entero de advertencias. No son la misma clase de acción.

El dibujo del rediseño quita la columna de tipo (Dynamic/Reserved) y deja sólo
«Remove» en cada fila. Eso perdería dos acciones reales de la API, así que se
mantienen las tres de upstream y la etiqueta de tipo.
*/

export interface LeasesProps {
  token: string | null
  node?: string
  /** `DhcpServer.canModify`: las dos conversiones (`WebServiceDhcpApi.cs:805,835`). */
  canModify?: boolean
  /** `DhcpServer.canDelete`: quitar una concesión (`WebServiceDhcpApi.cs:761`). */
  canDelete?: boolean
}

export function Leases({ token, node = '', canModify = true, canDelete = true }: LeasesProps) {
  const [leases, setLeases] = useState<DhcpLease[] | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [confirmar, setConfirmar] = useState<{ tipo: 'reserve' | 'dynamic'; i: number } | null>(null)
  const [quitar, setQuitar] = useState<number | null>(null)
  const [avisoModal, setAvisoModal] = useState<Aviso | null>(null)

  const cargar = useCallback(async () => {
    setLeases(null)
    setLeases(await listLeases(token, node))
  }, [token, node])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function convertir(i: number, tipo: 'reserve' | 'dynamic') {
    const lease = leases?.[i]
    setConfirmar(null)
    if (lease == null) return

    setOcupado(true)
    const outcome =
      tipo === 'reserve'
        ? await convertToReservedLease(token, lease.scope, lease.clientIdentifier, node)
        : await convertToDynamicLease(token, lease.scope, lease.clientIdentifier, node)
    setOcupado(false)

    if (outcome.kind !== 'ok') return

    // dhcp.js:104-109 — sólo cambia la etiqueta de la fila; no se recarga.
    const nuevo = tipo === 'reserve' ? 'Reserved' : 'Dynamic'
    setLeases((prev) => prev?.map((l, j) => (j === i ? { ...l, type: nuevo } : l)) ?? prev)
    setAviso(
      tipo === 'reserve'
        ? {
            type: 'success',
            title: 'Reserved!',
            text: 'The dynamic lease was converted to reserved lease successfully.',
          }
        : {
            type: 'success',
            title: 'Unreserved!',
            text: 'The reserved lease was converted to dynamic lease successfully.',
          },
    )
  }

  async function quitarLease() {
    const i = quitar
    const lease = i == null ? null : leases?.[i]
    if (i == null || lease == null) return

    setOcupado(true)
    const outcome = await removeLease(token, lease.scope, lease.clientIdentifier, node)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAvisoModal({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    setLeases((prev) => prev?.filter((_, j) => j !== i) ?? prev)
    setQuitar(null)
    setAviso({
      type: 'success',
      title: 'Lease Removed!',
      text: 'The DHCP lease was removed successfully.',
    })
  }

  if (leases == null) return <Loading />

  return (
    <div className={styles.wrap}>
      <SectionHeader
        seccion="DHCP"
        titulo="Leases"
        acciones={<><Button onClick={() => void cargar()}>Refresh</Button></>}
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
              <th>Scope</th>
              <th>MAC Address</th>
              <th>IP Address</th>
              <th />
              <th>Host Name</th>
              <th>Lease Obtained</th>
              <th>Lease Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {leases.map((l, i) => (
              <tr key={`${l.scope}/${l.clientIdentifier}`}>
                <td className={styles.mono}>{l.scope}</td>
                <td className={styles.mono}>{l.hardwareAddress}</td>
                <td className={styles.mono}>{l.address}</td>
                <td>
                  <Tag tone={l.type === 'Reserved' ? 'neutral' : 'ok'}>
                    {l.type}
                  </Tag>
                </td>
                <td className={styles.mono}>{l.hostName}</td>
                <td className={styles.fecha}>{fechaMinuto(l.leaseObtained)}</td>
                <td className={styles.fecha}>{fechaMinuto(l.leaseExpires)}</td>
                <td>
                  <div className={styles.rowacts}>
                    {/* dhcp.js:63-64 — cuál de las dos conversiones se ofrece
                        depende del tipo actual de la concesión. */}
                    {canModify && l.type === 'Dynamic' && (
                      <Button
                        size="sm"
                        disabled={ocupado}
                        onClick={() => setConfirmar({ tipo: 'reserve', i })}
                      >
                        Convert To Reserved Lease
                      </Button>
                    )}
                    {canModify && l.type !== 'Dynamic' && (
                      <Button
                        size="sm"
                        disabled={ocupado}
                        onClick={() => setConfirmar({ tipo: 'dynamic', i })}
                      >
                        Convert To Dynamic Lease
                      </Button>
                    )}
                    {canDelete && (
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={ocupado}
                        onClick={() => {
                          setAvisoModal(null)
                          setQuitar(i)
                        }}
                      >
                        Remove Lease
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
        {leases.length > 0 ? <b>Total Leases: {leases.length}</b> : 'No Lease Found'}
      </div>

      <Dialog
        open={confirmar !== null}
        onOpenChange={(o) => !o && setConfirmar(null)}
        title={confirmar?.tipo === 'dynamic' ? 'Convert To Dynamic Lease' : 'Convert To Reserved Lease'}
        acciones={
          <>
            <Button
              variant="primary"
              disabled={ocupado}
              onClick={() => confirmar && void convertir(confirmar.i, confirmar.tipo)}
            >
              OK
            </Button>
          </>
        }
        cerrar="Cancel"
      >
        <p className={styles.parrafo}>
          {confirmar?.tipo === 'dynamic'
            ? 'Are you sure you want to convert the reserved lease to dynamic lease?'
            : 'Are you sure you want to convert the dynamic lease to reserved lease?'}
        </p>
      </Dialog>

      {/* index.html:6587-6617 — el modal «Remove Lease?» completo, con sus dos
          advertencias, su recomendación y su lista de alternativas. */}
      <Dialog
        open={quitar !== null}
        onOpenChange={(o) => !o && setQuitar(null)}
        title="Remove Lease?"
        acciones={
          <>
            <Button variant="danger" disabled={ocupado} onClick={() => void quitarLease()}>
              Remove
            </Button>
          </>
        }
      >
        {avisoModal && (
          <Alert type={avisoModal.type} title={avisoModal.title} onDismiss={() => setAvisoModal(null)}>
            {avisoModal.text}
          </Alert>
        )}
        <p className={styles.parrafo}>
          <b>Warning!</b> Removing a DHCP lease from the server side will NOT remove the allocated IP
          address from the client side. Make sure that the client assigned this lease is not
          connected to the network before proceeding.
        </p>
        <p className={styles.parrafo}>
          <b>Warning!</b> Removing a DHCP lease may cause IP address conflict if the DHCP server
          assigns the same IP address to a new client while the old client is still connected to the
          network.
        </p>
        <p className={styles.parrafo}>
          It is not recommended to remove a DHCP lease when the client is still connected or may
          connect back later to the network before the lease expires. Use this option only as a last
          resort.
        </p>
        <p className={styles.parrafo}>
          Follow the recommendations below to avoid such a case that requires removing a DHCP lease:
        </p>
        <ul className={styles.lista}>
          <li>
            Use a shorter lease time such that a dynamically allocated lease expires quickly when the
            client exits the network.
          </li>
          <li>
            Use Exclusions to exclude IP address ranges from being dynamically allocated that you
            plan to assign manually to some of the devices on the network.
          </li>
          <li>
            Use Exclusions to make sure that you have unallocated addresses available in the DHCP
            scope to be assigned as reserved leases in future.
          </li>
          <li>
            Rely less on the assigned IP addresses by configuring a domain name for the DHCP scope
            and accessing all the devices using their domain names.
          </li>
        </ul>
        <p className={styles.parrafo}>Are you sure you want to remove the DHCP lease now?</p>
      </Dialog>
    </div>
  )
}
