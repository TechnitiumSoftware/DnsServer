import { useCallback, useEffect, useRef, useState } from 'react'
import {
  deleteZone,
  deleteZones,
  disableZone,
  enableZone,
  zoneState,
  typeLabel,
  exportZone,
  listZones,
  zoneNameOf,
  resyncZone,
  ZONE_TYPES,
  ZONES_PER_PAGE,
  type Zone,
} from '../../api/zones'
import { Button } from '../../ui/Button'
import { Field, Input, Select } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Tag, type TagTone } from '../../ui/Tag'
import { Menu, Separator } from '../../ui/Menu'
import { fechaMinuto as date } from '../../lib/dates'
import { textoDeEstado, pageWindow } from '../../lib/pagination'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import styles from './Zones.module.css'
import type { Notice, Confirmation } from './types'
import { Pagination } from '../../ui/Pagination'
import { noticeFromFailure } from '../../lib/notice'

/*
The zone list. A replica of `refreshZones` (zone.js:649) and of the six actions
hanging off each row.

Two things from the original that look odd here and are deliberate:

  · **The "Delete Zones" button deletes what is checked and uses the same
    endpoint** as the single delete, with the parameter in plural. When some of
    them fail, the alert is NOT an error: it is a `warning` counting how many
    failed.

  · **Which actions a row offers depends on the zone type**, through five
    different lists that half overlap (`showResyncMenu`, and the four `switch` of
    Import / Export / Convert / Clone). They are not made uniform.
*/

/** The types that offer each action, exactly as zone.js:760-880 enumerates them. */
const RESYNC = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']
const IMPORT = ['Primary', 'Forwarder']
const EXPORT = ['Primary', 'Forwarder', 'Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Catalog']
const CONVERT = ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog']
const CLONE = ['Primary', 'Forwarder']
/** `hideOptionsMenu` is false for the seven known types (zone.js:774-790). */
const WITH_OPTIONS = [...ZONE_TYPES] as string[]

export interface ZoneActions {
  onOpen: (zone: string) => void
  onImport: (zone: string) => void
  onConvert: (zone: string, type: string) => void
  onClone: (zone: string) => void
  onPermissions: (zone: string) => void
  onOptions: (zone: string) => void
}

export interface ZoneListProps extends ZoneActions {
  token: string | null
  node?: string
  canModify: boolean
  canDelete: boolean
  onNotice: (a: Notice) => void
  onConfirm: (c: Confirmation) => void
  onAdd: () => void
  /** Changes when something from outside (a modal) forces a re-read of the list. */
  refresh: number
}

export function ZoneList({
  token,
  node = '',
  canModify,
  canDelete,
  onNotice,
  onConfirm,
  onAdd,
  onOpen,
  onImport,
  onConvert,
  onClone,
  onPermissions,
  onOptions,
  refresh,
}: ZoneListProps) {
  const [zones, setZones] = useState<Zone[]>([])
  const [pageNumber, setPageNumber] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalZones, setTotalZones] = useState(0)
  const [busy, setBusy] = useState(false)
  const [checkedOnes, setChecked] = useState<string[]>([])

  // The filters are form state: they do not apply until "Go" is pressed,
  // just like upstream, where `refreshZones` reads them at that moment.
  const [filtroNombre, setFiltroNombre] = useState('')
  const [typeFilter, setFiltroTipo] = useState('')
  const [perPage, setPerPage] = useState(10)
  const [pageField, setPageField] = useState('1')

  const nombreRef = useRef<HTMLInputElement>(null)

  const load = useCallback(
    async (page: number) => {
      setBusy(true)
      const r = await listZones(token, {
        filterName: filtroNombre,
        filterType: typeFilter,
        pageNumber: page,
        zonesPerPage: perPage,
        node,
      })
      setBusy(false)

      if (r.kind !== 'ok') {
        // The server's message, not a guess about the network.
        onNotice(noticeFromFailure(r))
        return
      }

      const data = r.data
      setZones(data.zones)
      setPageNumber(data.pageNumber)
      setTotalPages(data.totalPages)
      setTotalZones(data.totalZones)
      setPageField(String(data.pageNumber))
      // `chkZonesTableCheckAll` is unchecked on every refresh (zone.js:938).
      setChecked([])
      nombreRef.current?.focus()
    },
    [token, node, filtroNombre, typeFilter, perPage, onNotice],
  )

  /*
  On mount and when something from outside asks for a re-read. The filters do
  NOT trigger a reload on their own: "Go" has to be pressed, just like upstream,
  where `refreshZones` reads them at that moment. That is why `cargar` goes by
  ref and not in the dependencies: were it there, typing in the filter would
  reload the list.
  */
  const loadRef = useRef(load)
  useEffect(() => {
    loadRef.current = load
  }, [load])
  useEffect(() => {
    void loadRef.current(1)
  }, [refresh])

  function irA(page: number) {
    void load(page)
  }

  function applyFilters() {
    const n = Number(pageField)
    void load(pageField === '' || Number.isNaN(n) ? 1 : n)
  }

  /** Runs a mutation and refreshes, with upstream's literal alert. */
  async function mutate(
    fn: () => Promise<{ kind: string; message?: string }>,
    success: Notice,
  ) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    await load(pageNumber)
    onNotice(success)
  }

  function enable(z: Zone) {
    const name = z.name === '' ? '.' : z.name
    void mutate(() => enableZone(token, name, node), {
      type: 'success',
      title: 'Zone Enabled!',
      text: `Zone '${name}' was enabled successfully.`,
    })
  }

  function disable(z: Zone) {
    const name = z.name === '' ? '.' : z.name
    onConfirm({
      title: 'Disable Zone',
      text: `Are you sure you want to disable the zone '${name}'?`,
      label: 'Disable',
      action: () =>
        mutate(() => disableZone(token, name, node), {
          type: 'success',
          title: 'Zone Disabled!',
          text: `Zone '${name}' was disabled successfully.`,
        }),
    })
  }

  function remove(z: Zone) {
    const name = z.name === '' ? '.' : z.name
    onConfirm({
      title: 'Delete Zone',
      text: `Are you sure you want to permanently delete the zone '${name}' and all its records?`,
      label: 'Delete',
      danger: true,
      action: () =>
        mutate(() => deleteZone(token, name, node), {
          type: 'success',
          title: 'Zone Deleted!',
          text: `Zone '${name}' was deleted successfully.`,
        }),
    })
  }

  function resincronizar(z: Zone) {
    const name = z.name === '' ? '.' : z.name
    // Two different texts: the secondary talks about AXFR and the rest about refresh.
    const text =
      z.type === 'Secondary'
        ? `The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${name}' zone?`
        : `The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${name}' zone?`

    onConfirm({
      title: 'Resync Zone',
      text,
      label: 'Resync',
      action: () =>
        mutate(() => resyncZone(token, name, node), {
          type: 'success',
          title: 'Resync Triggered!',
          text: `Zone '${name}' resync was triggered successfully. Please check the Logs for confirmation.`,
        }),
    })
  }

  async function runExport(z: Zone) {
    const name = z.name === '' ? '.' : z.name
    const r = await exportZone(token, name, node)
    if (!r.ok) return
    onNotice({ type: 'success', title: 'Zone Exported!', text: 'Zone file was exported successfully.' })
  }

  function deleteChecked() {
    if (checkedOnes.length === 0) {
      // A plain `alert()` in upstream, not a `showAlert` of the screen.
      onNotice({ type: 'warning', title: 'Missing!', text: 'Please select one or more zones to delete.' })
      return
    }

    const list = zones
      .filter((z) => checkedOnes.includes(z.name))
      .map((z) => (z.nameIdn == null ? (z.name === '' ? '.' : z.name) : `${z.nameIdn} (${z.name})`))

    onConfirm({
      title: 'Delete Zones',
      text: `Are you sure you want to permanently delete the following zones and all of their records?\n\n${list.join('\n')}`,
      label: 'Delete',
      danger: true,
      action: async () => {
        setBusy(true)
        const outcome = await deleteZones(token, checkedOnes, node)
        setBusy(false)

        if (outcome.kind !== 'ok') {
          onNotice(noticeFromFailure(outcome))
          return
        }

        await load(pageNumber)

        const failures = Object.keys(outcome.data.response.failed ?? {}).length
        if (failures === 0) {
          onNotice({
            type: 'success',
            title: 'Zones Deleted!',
            text: 'All selected zones were deleted successfully.',
          })
        } else {
          const total = (outcome.data.response.deleted?.length ?? 0) + failures
          onNotice({
            type: 'warning',
            title: 'Failed To Deleted!',
            text: `A total of ${failures} zone(s) of the selected ${total} zone(s) failed to delete. Please check error logs for more details.`,
          })
        }
      },
    })
  }

  const firstRow = (pageNumber - 1) * perPage + 1
  const state = textoDeEstado(firstRow, zones.length, totalZones, pageNumber, totalPages, 'zones')
  const pg = pageWindow(pageNumber, totalPages)
  const { rows: visibleZones, sort, toggle } = useOrden(KEYS, zones)

  const allChecked = zones.length > 0 && checkedOnes.length === zones.length

  // The last page is asked for with -1: the server works it out itself.
  const pagination = <Pagination window={pg} current={pageNumber} last={-1} onIr={irA} />

  return (
    <>
      <SectionHeader
        title="Zones"
        actions={<><Button variant="primary" disabled={!canModify || busy} onClick={onAdd}>
            Add Zone
          </Button>
          <Button variant="danger" disabled={!canDelete || busy} onClick={deleteChecked}>
            Delete Zones
          </Button></>}
      />

      <div className={styles.flt}>
        <div className={styles.filtAncho}>
          <Field label="Name">
            {(id) => (
              <Input
                id={id}
                ref={nombreRef}
                placeholder="abc or a* or *b* or a?c"
                value={filtroNombre}
                onChange={(e) => setFiltroNombre(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtMedio}>
          <Field label="Type">
            {(id) => (
              <Select id={id} value={typeFilter} onChange={(e) => setFiltroTipo(e.target.value)}>
                <option value="" />
                {ZONE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <div className={styles.fltShort}>
          <Field label="Page Number">
            {(id) => (
              <Input
                id={id}
                mono
                value={pageField}
                onChange={(e) => setPageField(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
              />
            )}
          </Field>
        </div>
        <div className={styles.fltShort}>
          <Field label="Zones Per Page">
            {(id) => (
              <Select id={id} value={String(perPage)} onChange={(e) => setPerPage(Number(e.target.value))}>
                {ZONES_PER_PAGE.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Button variant="primary" disabled={busy} onClick={applyFilters}>
          Go
        </Button>
      </div>

      <div className={styles.count}>
        <span>{state}</span>
        {pagination}
      </div>

      <Table
        header={
          <>
            {/* The checkbox is 18 px; it is pressed from anywhere in its cell. */}
            <th style={{ width: 38 }} className={tbl.checkCell}>
              <label>
                <input
                  type="checkbox"
                  aria-label="Select all zones"
                  checked={allChecked}
                  onChange={(e) => setChecked(e.target.checked ? zones.map((z) => z.name) : [])}
                />
              </label>
            </th>
            <th style={{ width: 34 }}>#</th>
            <Th field="zone" sort={sort} onSort={toggle}>Zone</Th>
            <Th field="type" sort={sort} onSort={toggle} style={{ width: 120 }}>Type</Th>
            <Th field="dnssec" sort={sort} onSort={toggle} style={{ width: 90 }}>DNSSEC</Th>
            <Th field="status" sort={sort} onSort={toggle} style={{ width: 120 }}>Status</Th>
            <Th
              field="serial"
              sort={sort}
              onSort={toggle}
              style={{ width: 110, textAlign: 'right' }}
            >
              Serial
            </Th>
            <Th field="expiry" sort={sort} onSort={toggle} style={{ width: 110 }}>Expiry</Th>
            <Th field="modified" sort={sort} onSort={toggle} style={{ width: 150 }}>
              Last Modified
            </Th>
            {/* The actions column reserved 230 px with three labels inside;
                with icons 120 is enough and the 110 left over go to the data,
                which is what the table is about. */}
            <th style={{ width: 120 }} />
          </>
        }
      >
        {visibleZones.length === 0 ? (
          <tr>
            <td colSpan={10} className={tbl.noRows}>
              No Zone Found
            </td>
          </tr>
        ) : (
          visibleZones.map((z, i) => (
            <ZoneRow
              key={z.name}
              zone={z}
              indice={firstRow + i}
              checked={checkedOnes.includes(z.name)}
              busy={busy}
              canModify={canModify}
              canDelete={canDelete}
              onMarcar={(v) =>
                setChecked((m) => (v ? [...m, z.name] : m.filter((n) => n !== z.name)))
              }
              onOpen={onOpen}
              onEnable={enable}
              onDisable={disable}
              onDelete={remove}
              onResync={resincronizar}
              onImport={onImport}
              onExport={runExport}
              onConvert={onConvert}
              onClone={onClone}
              onPermissions={onPermissions}
              onOptions={onOptions}
            />
          ))
        )}
      </Table>

      <div className={`${styles.count} ${styles.countPie}`}>
        <span>{state}</span>
        {pagination}
      </div>
    </>
  )
}

interface RowProps {
  zone: Zone
  indice: number
  checked: boolean
  busy: boolean
  canModify: boolean
  canDelete: boolean
  onMarcar: (v: boolean) => void
  onOpen: (zone: string) => void
  onEnable: (z: Zone) => void
  onDisable: (z: Zone) => void
  onDelete: (z: Zone) => void
  onResync: (z: Zone) => void
  onImport: (zone: string) => void
  onExport: (z: Zone) => void
  onConvert: (zone: string, type: string) => void
  onClone: (zone: string) => void
  onPermissions: (zone: string) => void
  onOptions: (zone: string) => void
}

/*
What each column sorts by is THE TEXT YOU SEE, just like upstream
(`sortTable('tableZonesBody', 1..8)`). That is why `Serial` is read as a string
and not as a number: that way the order matches the old console's.
*/
const KEYS: Keys<Zone> = {
  zone: (z) => zoneNameOf(z),
  type: (z) => typeLabel(z.type),
  dnssec: (z) =>
    z.dnssecStatus === 'SignedWithNSEC' || z.dnssecStatus === 'SignedWithNSEC3'
      ? z.hasDnssecPrivateKeys
        ? 'Signed'
        : 'Signed, no keys'
      : 'Unsigned',
  status: (z) => zoneState(z),
  serial: (z) => z.soaSerial,
  expiry: (z) => date(z.expiry),
  modified: (z) => date(z.lastModified),
}

function ZoneRow(p: RowProps) {
  const { zone: z } = p
  const name = z.name === '' ? '.' : z.name
  const state = zoneState(z)
  const signed = z.dnssecStatus === 'SignedWithNSEC' || z.dnssecStatus === 'SignedWithNSEC3'

  const tonoEstado: TagTone =
    state === 'Enabled'
      ? 'ok'
      : state === 'Expired' || state === 'Validation Failed'
        ? 'dan'
        : state === 'Sync Failed' || state === 'Notify Failed'
          ? 'warn'
          : 'neutral'

  /*
  The catalog the zone is a MEMBER of, and nothing else.

  Before, if the zone was itself a catalog, it got a tag with its own name: the
  cell said `catalogo.test` twice in a row and the `Type` column already said
  "Catalog". It informed of nothing. Upstream draws the tag only when there is
  membership (`zone.js:796`: `if (zones[i].catalog != null)`), so that was an
  addition of ours, not parity.
  */
  const catalogLabel =
    z.catalog != null ? { text: z.catalog, tono: 'neutral' as TagTone } : null

  return (
    <tr>
      <td className={tbl.checkCell}>
        <label>
          <input
            type="checkbox"
            aria-label={`Select ${name}`}
            checked={p.checked}
            onChange={(e) => p.onMarcar(e.target.checked)}
          />
        </label>
      </td>
      <td className={`${styles.num} ${tbl.number}`}>{p.indice}</td>
      {/* The monospacing goes on the CELL and the button inherits it: the
          shared class says `font-family: inherit` precisely for this, and putting
          it on the button depended on which module was emitted last. */}
      <td className={`${tbl.stacked} ${styles.zoneCell}`}>
        <button
          type="button"
          className={`${styles.zoneLink} ${tbl.entity}`}
          onClick={() => p.onOpen(name)}
        >
          {zoneNameOf(z)}
        </button>
        {catalogLabel && (
          <div className={styles.tags}>
            <Tag tone={catalogLabel.tono}>{catalogLabel.text}</Tag>
          </div>
        )}
      </td>
      {/* The type goes as text and not as a capsule: with Type, DNSSEC and
          Status all in capsules, three consecutive columns of pills read as a
          single smear and none of the three stood out. */}
      <td className={tbl.meta}>{typeLabel(z.type)}</td>
      <td>
        {/*
        Upstream leaves the cell EMPTY when the zone is not signed
        (zone.js:721-731), and a blank cell does not say "unsigned": it says "I
        do not know" or "it has not loaded". With 240 zones paginated ten at a
        time, "which ones do I still have to sign" could only be answered from
        the API.

        The three states are said with three different texts, not with the same
        text in two colours: without private keys the zone is signed but this
        server cannot re-sign it, which is not the same as being signed.
        */}
        {!signed ? (
          <Tag>Unsigned</Tag>
        ) : z.hasDnssecPrivateKeys ? (
          <Tag tone="info">Signed</Tag>
        ) : (
          <Tag>Signed, no keys</Tag>
        )}
      </td>
      <td>
        <Tag tone={tonoEstado}>{state}</Tag>
      </td>
      <td className={styles.mono}>{z.soaSerial ?? ' '}</td>
      <td className={styles.mono}>{date(z.expiry)}</td>
      <td className={`${styles.mono} ${tbl.meta}`}>{date(z.lastModified)}</td>
      <td className={tbl.actionsCell}>
        <div className={tbl.actions}>
          <RowAction
            icon="settings"
            name="Zone Options"
            disabled={!p.canModify || p.busy || !WITH_OPTIONS.includes(z.type)}
            onClick={() => p.onOptions(name)}
          />
          {/* The same icon for both states: which one applies is said by the
              "Status" column, three columns to the left. */}
          <RowAction
            icon="power"
            name={z.disabled ? 'Enable Zone' : 'Disable Zone'}
            disabled={!p.canModify || p.busy}
            onClick={() => (z.disabled ? p.onEnable(z) : p.onDisable(z))}
          />
          <Menu label={`Actions for ${name}`}>
            {(close) => (
              <>
                <button type="button" onClick={() => { close(); p.onOpen(name) }}>
                  Edit Zone
                </button>
                {RESYNC.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onResync(z) }}>
                    Resync
                  </button>
                )}
                {IMPORT.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onImport(name) }}>
                    Import Zone
                  </button>
                )}
                {EXPORT.includes(z.type) && (
                  <button type="button" onClick={() => { close(); void p.onExport(z) }}>
                    Export Zone
                  </button>
                )}
                {CONVERT.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onConvert(name, z.type) }}>
                    Convert Zone
                  </button>
                )}
                {CLONE.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { close(); p.onClone(name) }}>
                    Clone Zone
                  </button>
                )}
                <button type="button" onClick={() => { close(); p.onPermissions(name) }}>
                  Permissions
                </button>
                {/*
                Delete goes back into the menu, and this time with a reason. It
                was in the row so it would cost one click just as on the zone's
                own screen, but a detail screen is not a row: there you act on
                ONE object you are looking at, and here on one of two hundred and
                forty, with "Disable" right next to it and with no undo anywhere
                in this console.
                */}
                <Separator />
                <button type="button" data-variant="danger" disabled={!p.canDelete} onClick={() => { close(); p.onDelete(z) }}>
                  Delete Zone
                </button>
              </>
            )}
          </Menu>
        </div>
      </td>
    </tr>
  )
}
