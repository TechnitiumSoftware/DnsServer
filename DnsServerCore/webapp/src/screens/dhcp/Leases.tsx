import { useCallback, useEffect, useState } from 'react'
import {
  convertToDynamicLease,
  convertToReservedLease,
  listLeases,
  removeLease,
  type DhcpLease,
} from '../../api/dhcp'
import { Alert } from '../../ui/Alert'
import { Confirmar } from '../../ui/Confirmar'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import { fechaMinuto } from './fechas'
import type { Aviso } from './avisos'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'
import { AccionFila, Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import { Menu } from '../../ui/Menu'

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

/* `sortTable('tableDhcpLeasesBody', 0..6)`. */
const CLAVES: Claves<DhcpLease> = {
  scope: (l) => l.scope,
  mac: (l) => l.hardwareAddress,
  address: (l) => l.address,
  type: (l) => l.type,
  host: (l) => l.hostName,
  obtained: (l) => fechaMinuto(l.leaseObtained),
  expires: (l) => fechaMinuto(l.leaseExpires),
}

export function Leases({ token, node = '', canModify = true, canDelete = true }: LeasesProps) {
  const [leases, setLeases] = useState<DhcpLease[] | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [confirmar, setConfirmar] = useState<{ tipo: 'reserve' | 'dynamic'; i: number } | null>(null)
  const [quitar, setQuitar] = useState<number | null>(null)
  const [avisoModal, setAvisoModal] = useState<Aviso | null>(null)

  /*
  Un fallo al cargar NO se pinta como una lista vacía.

  Antes se decía «No Lease Found» cuando la llamada se había caído, que es lo
  mismo que enseña un servidor sin concesiones: la pantalla contestaba en falso y
  nadie sospecha de una respuesta que parece normal. Ahora el fallo se dice, con
  el mensaje que mandó el servidor.
  */
  const cargar = useCallback(async () => {
    setLeases(null)
    const r = await listLeases(token, node)
    if (r.kind === 'ok') {
      setLeases(r.data)
      return
    }
    setLeases([])
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
  const { filas: leasesVisibles, orden, alternar } = useOrden(CLAVES, leases ?? [])

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

      <Tabla
        cabecera={
          <>
            <Th campo="scope" orden={orden} onOrdenar={alternar}>Scope</Th>
            <Th campo="mac" orden={orden} onOrdenar={alternar}>MAC Address</Th>
            <Th campo="address" orden={orden} onOrdenar={alternar}>IP Address</Th>
            <Th campo="type" orden={orden} onOrdenar={alternar} nombre="Type" />
            <Th campo="host" orden={orden} onOrdenar={alternar}>Host Name</Th>
            <Th campo="obtained" orden={orden} onOrdenar={alternar}>Lease Obtained</Th>
            <Th campo="expires" orden={orden} onOrdenar={alternar}>Lease Expires</Th>
            <th className={tbl.celdaAcciones} />
          </>
        }
        vacia={leasesVisibles.length === 0}
        vacio="No Lease Found"
        columnas={8}
      >
        {leasesVisibles.map((l, i) => (
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
            <td className={tbl.celdaAcciones}>
              <div className={tbl.acciones}>
                {/* dhcp.js:63-64 — cuál de las dos conversiones se ofrece
                    depende del tipo actual de la concesión. */}
                {canModify && (
                  <AccionFila
                    icono="convertir"
                    nombre={
                      l.type === 'Dynamic'
                        ? 'Convert To Reserved Lease'
                        : 'Convert To Dynamic Lease'
                    }
                    disabled={ocupado}
                    onClick={() =>
                      setConfirmar({ tipo: l.type === 'Dynamic' ? 'reserve' : 'dynamic', i })
                    }
                  />
                )}
                {canDelete && (
                  <Menu etiqueta={`Actions for ${l.address}`}>
                    {(cerrar) => (
                      <button
                        type="button"
                        data-variant="danger"
                        disabled={ocupado}
                        onClick={() => { cerrar(); setAvisoModal(null); setQuitar(i) }}
                      >
                        Remove Lease
                      </button>
                    )}
                  </Menu>
                )}
              </div>
            </td>
          </tr>
        ))}
      </Tabla>

      <div className={styles.total}>
        {/* El pie es el recuento y nada más. Cuando no hay filas, quien lo dice
            es la propia tabla —con su fila centrada, como el resto de la
            consola y como upstream (`dhcp.js:74`)—; aquí quedaba flotando
            fuera del panel, bajo una tabla con el cuerpo en blanco. */}
        <span>{`Total Leases: ${leases.length}`}</span>
      </div>

      <Confirmar
        abierto={confirmar !== null}
        titulo={confirmar?.tipo === 'dynamic' ? 'Convert To Dynamic Lease' : 'Convert To Reserved Lease'}
        texto={
          confirmar?.tipo === 'dynamic'
            ? 'Are you sure you want to convert the reserved lease to dynamic lease?'
            : 'Are you sure you want to convert the dynamic lease to reserved lease?'
        }
        etiqueta="Convert"
        variante="primary"
        ocupado={ocupado}
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => confirmar && void convertir(confirmar.i, confirmar.tipo)}
      />

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
