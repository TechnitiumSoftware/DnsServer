import { useCallback, useEffect, useState } from 'react'
import {
  convertToDynamicLease,
  convertToReservedLease,
  listLeases,
  removeLease,
  type DhcpLease,
} from '../../api/dhcp'
import { Confirm } from '../../ui/Confirmar'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import { fechaMinuto } from './fechas'
import type { Notice } from './avisos'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import styles from './Dhcp.module.css'
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { noticeFromFailure } from '../../lib/aviso'
import { Notifier } from '../../ui/Avisador'

/*
DHCP › Leases (dhcp.js:37-199).

Three upstream details that are not visible in the mockup and that are kept here:

  1. **The table does NOT reload after an action.** Converting a lease changes
     that row's type tag and the two options in its menu; removing it deletes the
     row and recalculates the footer. In no case is the list asked for again.
  2. **The "Remove Lease" alert comes out INSIDE the modal when it fails** and on
     the screen when it succeeds: upstream passes `showAlert` the modal's own
     `divDhcpRemoveLeaseAlert` only in the error branch.
  3. **The two conversions are confirmed with a `confirm()`** and the delete with
     a whole modal of warnings. They are not the same class of action.

The redesign mockup drops the type column (Dynamic/Reserved) and leaves only
"Remove" on each row. That would lose two real API actions, so upstream's three
and the type tag are kept.
*/

export interface LeasesProps {
  token: string | null
  node?: string
  /** `DhcpServer.canModify`: the two conversions (`WebServiceDhcpApi.cs:805,835`). */
  canModify?: boolean
  /** `DhcpServer.canDelete`: removing a lease (`WebServiceDhcpApi.cs:761`). */
  canDelete?: boolean
}

/* `sortTable('tableDhcpLeasesBody', 0..6)`. */
const KEYS: Keys<DhcpLease> = {
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
  const [notice, setAviso] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirmar] = useState<{ type: 'reserve' | 'dynamic'; i: number } | null>(null)
  const [discard, setQuitar] = useState<number | null>(null)
  const [modalNotice, setAvisoModal] = useState<Notice | null>(null)

  /*
  A failure on load is NOT drawn as an empty list.

  It used to say "No Lease Found" when the call had fallen over, which is the same
  thing a server with no leases shows: the screen was answering falsely and nobody
  suspects a response that looks normal. Now the failure is said, with the message
  the server sent.
  */
  const load = useCallback(async () => {
    setLeases(null)
    const r = await listLeases(token, node)
    if (r.kind === 'ok') {
      setLeases(r.data)
      return
    }
    setLeases([])
    setAviso(noticeFromFailure(r))
  }, [token, node])

  useEffect(() => {
    void load()
  }, [load])

  // The hook goes BEFORE any return: otherwise it would stop being called as soon
  // as the table is loading.
  const { rows: leasesVisibles, sort, alternar } = useOrden(KEYS, leases ?? [])

  async function convert(i: number, type: 'reserve' | 'dynamic') {
    const lease = leases?.[i]
    setConfirmar(null)
    if (lease == null) return

    setBusy(true)
    const outcome =
      type === 'reserve'
        ? await convertToReservedLease(token, lease.scope, lease.clientIdentifier, node)
        : await convertToDynamicLease(token, lease.scope, lease.clientIdentifier, node)
    setBusy(false)

    if (outcome.kind !== 'ok') return

    // dhcp.js:104-109 — only the row's tag changes; nothing is reloaded.
    const blank = type === 'reserve' ? 'Reserved' : 'Dynamic'
    setLeases((prev) => prev?.map((l, j) => (j === i ? { ...l, type: blank } : l)) ?? prev)
    setAviso(
      type === 'reserve'
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

  async function discardLease() {
    const i = discard
    const lease = i == null ? null : leases?.[i]
    if (i == null || lease == null) return

    setBusy(true)
    const outcome = await removeLease(token, lease.scope, lease.clientIdentifier, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAvisoModal(noticeFromFailure(outcome))
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
        section="DHCP"
        titulo="Leases"
        actions={<><Button onClick={() => void load()}>Refresh</Button></>}
      />

      <Notifier notice={notice} onCerrar={() => setAviso(null)} />

      <Table
        header={
          <>
            <Th field="scope" sort={sort} onOrdenar={alternar}>Scope</Th>
            <Th field="mac" sort={sort} onOrdenar={alternar}>MAC Address</Th>
            <Th field="address" sort={sort} onOrdenar={alternar}>IP Address</Th>
            <Th field="type" sort={sort} onOrdenar={alternar} name="Type" />
            <Th field="host" sort={sort} onOrdenar={alternar}>Host Name</Th>
            <Th field="obtained" sort={sort} onOrdenar={alternar}>Lease Obtained</Th>
            <Th field="expires" sort={sort} onOrdenar={alternar}>Lease Expires</Th>
            <th className={tbl.celdaAcciones} />
          </>
        }
        isEmpty={leasesVisibles.length === 0}
        emptyText="No Lease Found"
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
            <td className={styles.date}>{fechaMinuto(l.leaseObtained)}</td>
            <td className={styles.date}>{fechaMinuto(l.leaseExpires)}</td>
            <td className={tbl.celdaAcciones}>
              <div className={tbl.actions}>
                {/* dhcp.js:63-64 — which of the two conversions is offered
                    depends on the lease's current type. */}
                {canModify && (
                  <AccionFila
                    icon="convert"
                    name={
                      l.type === 'Dynamic'
                        ? 'Convert To Reserved Lease'
                        : 'Convert To Dynamic Lease'
                    }
                    disabled={busy}
                    onClick={() =>
                      setConfirmar({ type: l.type === 'Dynamic' ? 'reserve' : 'dynamic', i })
                    }
                  />
                )}
                {canDelete && (
                  <Menu etiqueta={`Actions for ${l.address}`}>
                    {(close) => (
                      <button
                        type="button"
                        data-variant="danger"
                        disabled={busy}
                        onClick={() => { close(); setAvisoModal(null); setQuitar(i) }}
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
      </Table>

      <div className={styles.total}>
        {/* The footer is the count and nothing else. When there are no rows,
            the one that says so is the table itself —with its centred row, like
            the rest of the console and like upstream (`dhcp.js:74`)—; here it was
            left floating outside the panel, under a table with a blank body. */}
        <span>{`Total Leases: ${leases.length}`}</span>
      </div>

      <Confirm
        open={confirm !== null}
        titulo={confirm?.type === 'dynamic' ? 'Convert To Dynamic Lease' : 'Convert To Reserved Lease'}
        text={
          confirm?.type === 'dynamic'
            ? 'Are you sure you want to convert the reserved lease to dynamic lease?'
            : 'Are you sure you want to convert the dynamic lease to reserved lease?'
        }
        etiqueta="Convert"
        variante="primary"
        busy={busy}
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => confirm && void convert(confirm.i, confirm.type)}
      />

      {/* index.html:6587-6617 — the complete "Remove Lease?" modal, with its two
          warnings, its recommendation and its list of alternatives. */}
      <Dialog
        open={discard !== null}
        onOpenChange={(o) => !o && setQuitar(null)}
        title="Remove Lease?"
        actions={
          <>
            <Button variant="danger" disabled={busy} onClick={() => void discardLease()}>
              Remove
            </Button>
          </>
        }
      >
        <Notifier notice={modalNotice} onCerrar={() => setAvisoModal(null)} />
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
        <ul className={styles.list}>
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
