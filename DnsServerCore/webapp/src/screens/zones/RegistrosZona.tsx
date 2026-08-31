import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  cuerpoBorrado,
  cuerpoCambioDeEstado,
  deleteRecord,
  getRecords,
  updateRecord,
  zoneHasSvcbAutoHint,
  type ResourceRecord,
  type ZoneDetails,
} from '../../api/registros'
import {
  deleteZone,
  disableZone,
  enableZone,
  zoneState,
  typeLabel,
  exportZone,
  resyncZone,
  type Zone,
} from '../../api/zones'
import { Button } from '../../ui/Button'
import { Field, Input, Select } from '../../ui/Field'
import { DataCell } from './CeldaDatos'
import { fechaMinuto as date } from '../../lib/fechas'
import { Menu, Separador } from '../../ui/Menu'
import { filterBy } from './filtro'
import { textoDeEstado, pageWindow } from '../../lib/paginacion'
import { rowActions, recordCells, nombreRelativo, ocultarDnssec, type Cell } from './registro-vista'
import { zoneHeader, isSigned, writeHideDnssec, readHideDnssec } from './vista-zona'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty, Loading } from '../../ui/Empty'
import { Chip, Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import styles from './Zones.module.css'
import type { Notice, Confirmation } from './tipos'
import { Pagination } from '../../ui/Paginacion'
import { noticeFromFailure } from '../../lib/aviso'

/*
A zone's records. A replica of `showEditZone` (zone.js:3079) and
`showEditZonePage` (3500).

**Here the pagination is the client's**, the opposite of the zone list:
`zones/records/get` does not paginate, it brings the whole zone and upstream cuts
it in the browser. If this were done with a table library's default pagination,
the zone list would break and this one would not, or the other way round; that is
why both are written by hand and kept apart.
*/

const RECORDS_PER_PAGE = [10, 25, 50] as const

export interface ZoneRecordsProps {
  zone: string
  token: string | null
  node?: string
  canModify: boolean
  canDelete: boolean
  onVolver: () => void
  onNotice: (a: Notice) => void
  onConfirm: (c: Confirmation) => void
  onAddRecord: (zoneInfo: ZoneDetails, records: ResourceRecord[]) => void
  onEditRecord: (zoneInfo: ZoneDetails, record: ResourceRecord, records: ResourceRecord[]) => void
  onImport: (zone: string) => void
  onConvert: (zone: string, type: string) => void
  onClone: (zone: string) => void
  onPermissions: (zone: string) => void
  onOptions: (zone: string) => void
  onSign: (zone: string) => void
  onUnsign: (zone: string) => void
  onVerDs: (zone: string) => void
  onPropiedadesDnssec: (zone: string) => void
  /** Changes when an external modal forces a re-read of the zone. */
  refresco: number
  /*
  The expiry TTL left over in the record modal. It is NOT a whim:
  `updateRecordState` reads it from the modal's field instead of the row, so
  disabling a record sends whatever was left there from last time —or empty if
  the modal has not been opened. It is a bug of upstream's and it is replicated;
  see CONVENCIONES.md.
  */
  expiryTtlDelModal: string
}

/*
`sortTable('tableEditZoneBody', 0..4)` in upstream, which sorts by the cell's
text. "Data" is read through its already-formatted cells, which is what you see.

Upstream's `#` column is sortable too and here it is not: sorting by the row
number the sort itself has just handed out leads nowhere.
*/
function cellText(c: Cell): string {
  switch (c.clase) {
    case 'value':
      return c.text
    case 'pairs':
      return c.pairs.map((p) => `${p.label} ${p.value}`).join(' ')
    case 'lines':
      return c.lines.join(' ')
    case 'table':
      return [c.headers, ...c.rows].map((f) => f.join(' ')).join(' ')
  }
}

const KEYS: Keys<ResourceRecord> = {
  name: (r) => r.name,
  type: (r) => r.type,
  ttl: (r) => r.ttl,
  data: (r) => recordCells(r).map(cellText).join(' '),
}

export function ZoneRecords(p: ZoneRecordsProps) {
  const { zone, token, node = '', onNotice } = p

  const [zoneInfo, setZoneInfo] = useState<ZoneDetails | null>(null)
  const [records, setRecords] = useState<ResourceRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [ocultarDnssecRegs, setOcultarDnssecRegs] = useState(readHideDnssec)

  const [filtroNombre, setFiltroNombre] = useState('')
  const [filtroTipo, setFiltroTipo] = useState('')
  const [perPage, setPerPage] = useState(10)
  const [page, setPage] = useState(1)

  const load = useCallback(async () => {
    setLoading(true)
    const r = await getRecords(token, zone, node)
    setLoading(false)

    if (r == null) {
      onNotice({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
      return
    }
    setZoneInfo(r.zone)
    setRecords(r.records)
  }, [token, zone, node, onNotice])

  useEffect(() => {
    void load()
  }, [load, p.refresco])

  // The DNSSEC filtering comes before the name/type filter, just as in
  // upstream: `editZoneRecords` ya llega recortado a `showEditZonePage`.
  const visibles = useMemo(() => {
    const signed = isSigned(zoneInfo?.dnssecStatus)
    const base = ocultarDnssecRegs && signed ? ocultarDnssec(records) : records
    return filterBy(base, { name: filtroNombre, type: filtroTipo }, zone)
  }, [records, ocultarDnssecRegs, zoneInfo, filtroNombre, filtroTipo, zoneInfo])

  const { rows: sorted, sort, toggle } = useOrden(KEYS, visibles)

  const totalPages = Math.max(1, Math.ceil(visibles.length / perPage))
  const currentPage = Math.min(Math.max(page, 1), totalPages)
  const inicio = (currentPage - 1) * perPage
  const onPage = sorted.slice(inicio, inicio + perPage)

  const cab = zoneInfo ? zoneHeader(zoneInfo.type, zoneInfo.dnssecStatus) : null

  /** Runs a mutation on a record and reloads the whole zone. */
  async function mutateRecord(fn: () => Promise<{ kind: string; message?: string }>, exito: Notice) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    await load()
    onNotice(exito)
  }

  function cambiarEstado(r: ResourceRecord, disable: boolean) {
    const name = r.name === '' ? '.' : r.name
    const pistas = zoneHasSvcbAutoHint(records, r.type === 'A', r.type === 'AAAA')
    const body = {
      ...cuerpoCambioDeEstado(zone, r, disable, pistas),
      expiryTtl: p.expiryTtlDelModal,
    }

    const ejecutar = () =>
      mutateRecord(
        () => updateRecord(token, body, node),
        disable
          ? { type: 'success', title: 'Record Disabled!', text: 'Resource record was disabled successfully.' }
          : { type: 'success', title: 'Record Enabled!', text: 'Resource record was enabled successfully.' },
      )

    // Only disabling asks; enabling does not (zone.js:6241).
    if (!disable) {
      void ejecutar()
      return
    }

    p.onConfirm({
      title: 'Disable Record',
      text: `Are you sure to disable the ${r.type} record '${name}'?`,
      label: 'Disable',
      action: ejecutar,
    })
  }

  function removeRecord(r: ResourceRecord) {
    const name = r.name === '' ? '.' : r.name
    const pistas = zoneHasSvcbAutoHint(records, r.type === 'A', r.type === 'AAAA')
    const body = cuerpoBorrado(zone, r)
    if (r.type === 'A' || r.type === 'AAAA') body.updateSvcbHints = String(pistas)

    p.onConfirm({
      title: 'Delete Record',
      text: `Are you sure to permanently delete the ${r.type} record '${name}'?`,
      label: 'Delete',
      danger: true,
      action: () =>
        mutateRecord(() => deleteRecord(token, body, node), {
          type: 'success',
          title: 'Record Deleted!',
          text: 'Resource record was deleted successfully.',
        }),
    })
  }

  /* ── Actions on the whole zone ─────────────────────────────────────── */

  async function mutateZone(fn: () => Promise<{ kind: string; message?: string }>, exito: Notice, volver = false) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    onNotice(exito)
    if (volver) p.onVolver()
    else await load()
  }

  function doEnableZone() {
    void mutateZone(() => enableZone(token, zone, node), {
      type: 'success',
      title: 'Zone Enabled!',
      text: `Zone '${zone}' was enabled successfully.`,
    })
  }

  function doDisableZone() {
    p.onConfirm({
      title: 'Disable Zone',
      text: `Are you sure you want to disable the zone '${zone}'?`,
      label: 'Disable',
      action: () =>
        mutateZone(() => disableZone(token, zone, node), {
          type: 'success',
          title: 'Zone Disabled!',
          text: `Zone '${zone}' was disabled successfully.`,
        }),
    })
  }

  function removeZone() {
    p.onConfirm({
      title: 'Delete Zone',
      text: `Are you sure you want to permanently delete the zone '${zone}' and all its records?`,
      label: 'Delete',
      danger: true,
      action: () =>
        mutateZone(
          () => deleteZone(token, zone, node),
          { type: 'success', title: 'Zone Deleted!', text: `Zone '${zone}' was deleted successfully.` },
          true,
        ),
    })
  }

  function resincronizar() {
    if (zoneInfo == null) return
    const text =
      zoneInfo.type === 'Secondary'
        ? `The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${zone}' zone?`
        : `The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${zone}' zone?`

    p.onConfirm({
      title: 'Resync Zone',
      text,
      label: 'Resync',
      action: () =>
        mutateZone(() => resyncZone(token, zone, node), {
          type: 'success',
          title: 'Resync Triggered!',
          text: `Zone '${zone}' resync was triggered successfully. Please check the Logs for confirmation.`,
        }),
    })
  }

  async function runExport() {
    const r = await exportZone(token, zone, node)
    if (!r.ok) return
    onNotice({ type: 'success', title: 'Zone Exported!', text: 'Zone file was exported successfully.' })
  }

  function toggleDnssec() {
    const blank = !ocultarDnssecRegs
    setOcultarDnssecRegs(blank)
    writeHideDnssec(blank)
  }

  if (loading && zoneInfo == null) {
    return <Loading>Loading zone…</Loading>
  }

  if (zoneInfo == null) {
    return (
      <Empty title="Unable to open the zone">Go back to the list and try again.</Empty>
    )
  }

  const state = zoneState(zoneInfo as unknown as Zone)
  const signed = isSigned(zoneInfo.dnssecStatus)
  const text = textoDeEstado(inicio + 1, onPage.length, visibles.length, currentPage, totalPages, 'records')
  const pg = pageWindow(currentPage, totalPages)

  /* Here the last page is calculated on the client: the records are all
     loaded, there is no need to ask the server. */
  const pagination = (
    <Pagination ventana={pg} current={currentPage} last={totalPages} onIr={setPage} />
  )

  return (
    <>
      <SectionHeader
        section="Zones"
        onVolver={p.onVolver}
        title={zone === '.' ? '<root>' : zone}
        labels={
          <>
            <Tag>{typeLabel(zoneInfo.type)}</Tag>
            <Tag tone={state === 'Enabled' ? 'ok' : 'neutral'}>{state}</Tag>
            {signed && (
              <Tag tone="info">DNSSEC</Tag>
            )}
            {zoneInfo.catalog != null && <Tag>{zoneInfo.catalog}</Tag>}
          </>
        }
        actions={
          <>
            {cab?.addRecord && (
              <Button
                variant="primary"
                disabled={!p.canModify || busy}
                onClick={() => p.onAddRecord(zoneInfo, records)}
              >
                Add Record
              </Button>
            )}
            {zoneInfo.disabled ? (
              <Button disabled={!p.canModify || busy} onClick={doEnableZone}>
                Enable Zone
              </Button>
            ) : (
              <Button disabled={!p.canModify || busy} onClick={doDisableZone}>
                Disable Zone
              </Button>
            )}
            <Button variant="danger" disabled={!p.canDelete || busy} onClick={removeZone}>
              Delete Zone
            </Button>

            <Menu label="Zone actions" rotulo="Options">
              {(close) => (
                <>
                  {cab?.resync && (
                    <button type="button" disabled={!p.canModify} onClick={() => { close(); resincronizar() }}>
                      Resync
                    </button>
                  )}
                  {cab?.runImport && (
                    <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onImport(zone) }}>
                      Import Zone
                    </button>
                  )}
                  {cab?.runExport && (
                    <button type="button" onClick={() => { close(); void runExport() }}>
                      Export Zone
                    </button>
                  )}
                  {cab?.convert && (
                    <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onConvert(zone, zoneInfo.type) }}>
                      Convert Zone
                    </button>
                  )}
                  {cab?.clone && (
                    <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onClone(zone) }}>
                      Clone Zone
                    </button>
                  )}
                  {cab?.options && (
                    <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onOptions(zone) }}>
                      Zone Options
                    </button>
                  )}
                  {cab?.permissions && (
                    <button type="button" onClick={() => { close(); p.onPermissions(zone) }}>
                      Permissions
                    </button>
                  )}
                </>
              )}
            </Menu>

            {cab?.dnssec && (
              <Menu label="DNSSEC actions" rotulo="DNSSEC">
                {(close) => (
                  <>
                    {cab.sign && (
                      <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onSign(zone) }}>
                        Sign Zone
                      </button>
                    )}
                    {cab.toggleDnssecRecords && (
                      <button type="button" onClick={() => { close(); toggleDnssec() }}>
                        {ocultarDnssecRegs ? 'Show DNSSEC Records' : 'Hide DNSSEC Records'}
                      </button>
                    )}
                    {cab.verDs && (
                      <button type="button" onClick={() => { close(); p.onVerDs(zone) }}>
                        View DS Info
                      </button>
                    )}
                    {cab.propiedades && (
                      <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onPropiedadesDnssec(zone) }}>
                        DNSSEC Properties
                      </button>
                    )}
                    {cab.unsign && (
                      <>
                        <Separador />
                        <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onUnsign(zone) }}>
                          Unsign Zone
                        </button>
                      </>
                    )}
                  </>
                )}
              </Menu>
            )}
          </>
        }
      />

      <div className={styles.filt}>
        <div className={styles.filtAncho}>
          <Field label="Name">
            {(id) => (
              <Input
                id={id}
                placeholder="abc or a* or *b* or a?c"
                value={filtroNombre}
                onChange={(e) => { setFiltroNombre(e.target.value); setPage(1) }}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtCorto}>
          <Field label="Type">
            {(id) => (
              <Input
                id={id}
                value={filtroTipo}
                onChange={(e) => { setFiltroTipo(e.target.value); setPage(1) }}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtCorto}>
          <Field label="Records Per Page">
            {(id) => (
              <Select
                id={id}
                value={String(perPage)}
                onChange={(e) => { setPerPage(Number(e.target.value)); setPage(1) }}
              >
                {RECORDS_PER_PAGE.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
      </div>

      <div className={styles.count}>
        <span>{text}</span>
        {pagination}
      </div>

      <Table
        header={
          <>
            <th style={{ width: 34 }}>#</th>
            <Th field="name" sort={sort} onSort={toggle} style={{ width: 110 }}>Name</Th>
            <Th field="type" sort={sort} onSort={toggle} style={{ width: 80 }}>Type</Th>
            <Th field="ttl" sort={sort} onSort={toggle} style={{ width: 110 }}>TTL</Th>
            <Th field="data" sort={sort} onSort={toggle}>Data</Th>
            {/* The actions column reserved 230 px with three labels inside;
                with icons 120 is enough and the 110 left over go to the data,
                which is what the table is about. */}
            <th style={{ width: 120 }} />
          </>
        }
      >
        {onPage.length === 0 ? (
          <tr>
            <td colSpan={6} className={tbl.noRows}>
              No Record Found
            </td>
          </tr>
        ) : (
          onPage.map((r, i) => {
            const actions = rowActions(zoneInfo.type, r.type)
            return (
              <tr key={`${r.name}|${r.type}|${inicio + i}`}>
                <td className={styles.num}>{inicio + i + 1}</td>
                <td className={`${styles.mono}`}>{nombreRelativo(r.name, zone)}</td>
                <td>
                  <Chip>{r.type}</Chip>
                  {r.disabled && (
                    <div className={styles.tags}>
                      <Tag>Disabled</Tag>
                    </div>
                  )}
                </td>
                <td className={styles.ttl}>
                  {r.ttl} <small>({r.ttlString})</small>
                </td>
                <td>
                  <DataCell record={r} notifyFailedFor={zoneInfo.notifyFailedFor} />
                </td>
                <td className={tbl.actionsCell}>
                  {!actions.ocultas && (
                    <div className={tbl.actions}>
                      <RowAction
                        icon="edit"
                        name="Edit Record"
                        disabled={!p.canModify || busy}
                        onClick={() => p.onEditRecord(zoneInfo, r, records)}
                      />
                      <RowAction
                        icon="power"
                        name={r.disabled ? 'Enable Record' : 'Disable Record'}
                        disabled={actions.editingOnly || !p.canModify || busy}
                        onClick={() => cambiarEstado(r, !r.disabled)}
                      />
                      {/* Delete, inside the menu: the same rule as in the zone
                          list. */}
                      <Menu label={`Actions for ${nombreRelativo(r.name, zone)} ${r.type}`}>
                        {(close) => (
                          <button
                            type="button"
                            disabled={actions.editingOnly || !p.canDelete || busy}
                            onClick={() => { close(); removeRecord(r) }}
                          >
                            Delete Record
                          </button>
                        )}
                      </Menu>
                    </div>
                  )}
                </td>
              </tr>
            )
          })
        )}
      </Table>

      <div className={`${styles.count} ${styles.countPie}`}>
        <span>{text}</span>
        {pagination}
      </div>

      {/* The secondary zone's expiry, which upstream draws next to the title. */}
      {'expiry' in zoneInfo && (zoneInfo as { expiry?: string }).expiry != null && (
        <div className={styles.meta}>Expiry: {date((zoneInfo as { expiry?: string }).expiry)}</div>
      )}
    </>
  )
}
