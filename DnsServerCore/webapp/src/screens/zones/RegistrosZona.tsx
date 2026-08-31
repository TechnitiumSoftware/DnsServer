import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  cuerpoBorrado,
  cuerpoCambioDeEstado,
  deleteRecord,
  getRecords,
  updateRecord,
  zonaTienePistaSvcbAuto,
  type ResourceRecord,
  type ZonaDeRegistros,
} from '../../api/registros'
import {
  deleteZone,
  disableZone,
  enableZone,
  estadoDeZona,
  etiquetaTipo,
  exportZone,
  resyncZone,
  type Zone,
} from '../../api/zones'
import { Button } from '../../ui/Button'
import { Field, Input, Select } from '../../ui/Field'
import { CeldaDatos } from './CeldaDatos'
import { fechaMinuto as date } from '../../lib/fechas'
import { Menu, Separador } from '../../ui/Menu'
import { filtrar } from './filtro'
import { textoDeEstado, ventanaDePaginas } from '../../lib/paginacion'
import { accionesDeFila, celdasDeRegistro, nombreRelativo, ocultarDnssec, type Cell } from './registro-vista'
import { cabeceraDeZona, isSigned, guardarOcultarDnssec, leerOcultarDnssec } from './vista-zona'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty, Loading } from '../../ui/Empty'
import { Chip, Tag } from '../../ui/Tag'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import styles from './Zones.module.css'
import type { Aviso, Confirmation } from './tipos'
import { Pagination } from '../../ui/Paginacion'
import { avisoDeFallo } from '../../lib/aviso'

/*
A zone's records. A replica of `showEditZone` (zone.js:3079) and
`showEditZonePage` (3500).

**Here the pagination is the client's**, the opposite of the zone list:
`zones/records/get` does not paginate, it brings the whole zone and upstream cuts
it in the browser. If this were done with a table library's default pagination,
the zone list would break and this one would not, or the other way round; that is
why both are written by hand and kept apart.
*/

const REGISTROS_POR_PAGINA = [10, 25, 50] as const

export interface RegistrosZonaProps {
  zone: string
  token: string | null
  node?: string
  canModify: boolean
  canDelete: boolean
  onVolver: () => void
  onAviso: (a: Aviso) => void
  onConfirmar: (c: Confirmation) => void
  onAnadirRegistro: (zoneInfo: ZonaDeRegistros, records: ResourceRecord[]) => void
  onEditarRegistro: (zoneInfo: ZonaDeRegistros, record: ResourceRecord, records: ResourceRecord[]) => void
  onImportar: (zone: string) => void
  onConvertir: (zone: string, type: string) => void
  onClonar: (zone: string) => void
  onPermisos: (zone: string) => void
  onOpciones: (zone: string) => void
  onFirmar: (zone: string) => void
  onDesfirmar: (zone: string) => void
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
function textoDeCelda(c: Cell): string {
  switch (c.clase) {
    case 'value':
      return c.text
    case 'pairs':
      return c.pares.map((p) => `${p.etiqueta} ${p.value}`).join(' ')
    case 'lines':
      return c.lines.join(' ')
    case 'table':
      return [c.cabeceras, ...c.rows].map((f) => f.join(' ')).join(' ')
  }
}

const KEYS: Keys<ResourceRecord> = {
  name: (r) => r.name,
  type: (r) => r.type,
  ttl: (r) => r.ttl,
  data: (r) => celdasDeRegistro(r).map(textoDeCelda).join(' '),
}

export function RegistrosZona(p: RegistrosZonaProps) {
  const { zone, token, node = '', onAviso } = p

  const [zoneInfo, setZoneInfo] = useState<ZonaDeRegistros | null>(null)
  const [records, setRegistros] = useState<ResourceRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [ocultarDnssecRegs, setOcultarDnssecRegs] = useState(leerOcultarDnssec)

  const [filtroNombre, setFiltroNombre] = useState('')
  const [filtroTipo, setFiltroTipo] = useState('')
  const [porPagina, setPorPagina] = useState(10)
  const [page, setPagina] = useState(1)

  const cargar = useCallback(async () => {
    setLoading(true)
    const r = await getRecords(token, zone, node)
    setLoading(false)

    if (r == null) {
      onAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
      return
    }
    setZoneInfo(r.zone)
    setRegistros(r.records)
  }, [token, zone, node, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar, p.refresco])

  // The DNSSEC filtering comes before the name/type filter, just as in
  // upstream: `editZoneRecords` ya llega recortado a `showEditZonePage`.
  const visibles = useMemo(() => {
    const signed = isSigned(zoneInfo?.dnssecStatus)
    const base = ocultarDnssecRegs && signed ? ocultarDnssec(records) : records
    return filtrar(base, { name: filtroNombre, tipo: filtroTipo }, zone)
  }, [records, ocultarDnssecRegs, zoneInfo, filtroNombre, filtroTipo, zoneInfo])

  const { rows: ordenadas, orden, alternar } = useOrden(KEYS, visibles)

  const totalPages = Math.max(1, Math.ceil(visibles.length / porPagina))
  const paginaActual = Math.min(Math.max(page, 1), totalPages)
  const inicio = (paginaActual - 1) * porPagina
  const enPagina = ordenadas.slice(inicio, inicio + porPagina)

  const cab = zoneInfo ? cabeceraDeZona(zoneInfo.type, zoneInfo.dnssecStatus) : null

  /** Runs a mutation on a record and reloads the whole zone. */
  async function mutarRegistro(fn: () => Promise<{ kind: string; message?: string }>, exito: Aviso) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    await cargar()
    onAviso(exito)
  }

  function cambiarEstado(r: ResourceRecord, deshabilitar: boolean) {
    const name = r.name === '' ? '.' : r.name
    const pistas = zonaTienePistaSvcbAuto(records, r.type === 'A', r.type === 'AAAA')
    const body = {
      ...cuerpoCambioDeEstado(zone, r, deshabilitar, pistas),
      expiryTtl: p.expiryTtlDelModal,
    }

    const ejecutar = () =>
      mutarRegistro(
        () => updateRecord(token, body, node),
        deshabilitar
          ? { type: 'success', title: 'Record Disabled!', text: 'Resource record was disabled successfully.' }
          : { type: 'success', title: 'Record Enabled!', text: 'Resource record was enabled successfully.' },
      )

    // Only disabling asks; enabling does not (zone.js:6241).
    if (!deshabilitar) {
      void ejecutar()
      return
    }

    p.onConfirmar({
      titulo: 'Disable Record',
      text: `Are you sure to disable the ${r.type} record '${name}'?`,
      etiqueta: 'Disable',
      action: ejecutar,
    })
  }

  function borrarRegistro(r: ResourceRecord) {
    const name = r.name === '' ? '.' : r.name
    const pistas = zonaTienePistaSvcbAuto(records, r.type === 'A', r.type === 'AAAA')
    const body = cuerpoBorrado(zone, r)
    if (r.type === 'A' || r.type === 'AAAA') body.updateSvcbHints = String(pistas)

    p.onConfirmar({
      titulo: 'Delete Record',
      text: `Are you sure to permanently delete the ${r.type} record '${name}'?`,
      etiqueta: 'Delete',
      peligro: true,
      action: () =>
        mutarRegistro(() => deleteRecord(token, body, node), {
          type: 'success',
          title: 'Record Deleted!',
          text: 'Resource record was deleted successfully.',
        }),
    })
  }

  /* ── Actions on the whole zone ─────────────────────────────────────── */

  async function mutarZona(fn: () => Promise<{ kind: string; message?: string }>, exito: Aviso, volver = false) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    onAviso(exito)
    if (volver) p.onVolver()
    else await cargar()
  }

  function habilitarZona() {
    void mutarZona(() => enableZone(token, zone, node), {
      type: 'success',
      title: 'Zone Enabled!',
      text: `Zone '${zone}' was enabled successfully.`,
    })
  }

  function deshabilitarZona() {
    p.onConfirmar({
      titulo: 'Disable Zone',
      text: `Are you sure you want to disable the zone '${zone}'?`,
      etiqueta: 'Disable',
      action: () =>
        mutarZona(() => disableZone(token, zone, node), {
          type: 'success',
          title: 'Zone Disabled!',
          text: `Zone '${zone}' was disabled successfully.`,
        }),
    })
  }

  function borrarZona() {
    p.onConfirmar({
      titulo: 'Delete Zone',
      text: `Are you sure you want to permanently delete the zone '${zone}' and all its records?`,
      etiqueta: 'Delete',
      peligro: true,
      action: () =>
        mutarZona(
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

    p.onConfirmar({
      titulo: 'Resync Zone',
      text,
      etiqueta: 'Resync',
      action: () =>
        mutarZona(() => resyncZone(token, zone, node), {
          type: 'success',
          title: 'Resync Triggered!',
          text: `Zone '${zone}' resync was triggered successfully. Please check the Logs for confirmation.`,
        }),
    })
  }

  async function exportar() {
    const r = await exportZone(token, zone, node)
    if (!r.ok) return
    onAviso({ type: 'success', title: 'Zone Exported!', text: 'Zone file was exported successfully.' })
  }

  function alternarDnssec() {
    const nuevo = !ocultarDnssecRegs
    setOcultarDnssecRegs(nuevo)
    guardarOcultarDnssec(nuevo)
  }

  if (loading && zoneInfo == null) {
    return <Loading>Loading zone…</Loading>
  }

  if (zoneInfo == null) {
    return (
      <Empty titulo="Unable to open the zone">Go back to the list and try again.</Empty>
    )
  }

  const state = estadoDeZona(zoneInfo as unknown as Zone)
  const signed = isSigned(zoneInfo.dnssecStatus)
  const text = textoDeEstado(inicio + 1, enPagina.length, visibles.length, paginaActual, totalPages, 'records')
  const pg = ventanaDePaginas(paginaActual, totalPages)

  /* Here the last page is calculated on the client: the records are all
     loaded, there is no need to ask the server. */
  const pagination = (
    <Pagination ventana={pg} current={paginaActual} last={totalPages} onIr={setPagina} />
  )

  return (
    <>
      <SectionHeader
        section="Zones"
        onVolver={p.onVolver}
        titulo={zone === '.' ? '<root>' : zone}
        etiquetas={
          <>
            <Tag>{etiquetaTipo(zoneInfo.type)}</Tag>
            <Tag tone={state === 'Enabled' ? 'ok' : 'neutral'}>{state}</Tag>
            {signed && (
              <Tag tone="info">DNSSEC</Tag>
            )}
            {zoneInfo.catalog != null && <Tag>{zoneInfo.catalog}</Tag>}
          </>
        }
        actions={
          <>
            {cab?.anadirRegistro && (
              <Button
                variant="primary"
                disabled={!p.canModify || busy}
                onClick={() => p.onAnadirRegistro(zoneInfo, records)}
              >
                Add Record
              </Button>
            )}
            {zoneInfo.disabled ? (
              <Button disabled={!p.canModify || busy} onClick={habilitarZona}>
                Enable Zone
              </Button>
            ) : (
              <Button disabled={!p.canModify || busy} onClick={deshabilitarZona}>
                Disable Zone
              </Button>
            )}
            <Button variant="danger" disabled={!p.canDelete || busy} onClick={borrarZona}>
              Delete Zone
            </Button>

            <Menu etiqueta="Zone actions" rotulo="Options">
              {(cerrar) => (
                <>
                  {cab?.resync && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); resincronizar() }}>
                      Resync
                    </button>
                  )}
                  {cab?.importar && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onImportar(zone) }}>
                      Import Zone
                    </button>
                  )}
                  {cab?.exportar && (
                    <button type="button" onClick={() => { cerrar(); void exportar() }}>
                      Export Zone
                    </button>
                  )}
                  {cab?.convertir && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onConvertir(zone, zoneInfo.type) }}>
                      Convert Zone
                    </button>
                  )}
                  {cab?.clonar && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onClonar(zone) }}>
                      Clone Zone
                    </button>
                  )}
                  {cab?.options && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onOpciones(zone) }}>
                      Zone Options
                    </button>
                  )}
                  {cab?.permissions && (
                    <button type="button" onClick={() => { cerrar(); p.onPermisos(zone) }}>
                      Permissions
                    </button>
                  )}
                </>
              )}
            </Menu>

            {cab?.dnssec && (
              <Menu etiqueta="DNSSEC actions" rotulo="DNSSEC">
                {(cerrar) => (
                  <>
                    {cab.firmar && (
                      <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onFirmar(zone) }}>
                        Sign Zone
                      </button>
                    )}
                    {cab.alternarRegistrosDnssec && (
                      <button type="button" onClick={() => { cerrar(); alternarDnssec() }}>
                        {ocultarDnssecRegs ? 'Show DNSSEC Records' : 'Hide DNSSEC Records'}
                      </button>
                    )}
                    {cab.verDs && (
                      <button type="button" onClick={() => { cerrar(); p.onVerDs(zone) }}>
                        View DS Info
                      </button>
                    )}
                    {cab.propiedades && (
                      <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onPropiedadesDnssec(zone) }}>
                        DNSSEC Properties
                      </button>
                    )}
                    {cab.desfirmar && (
                      <>
                        <Separador />
                        <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onDesfirmar(zone) }}>
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
                onChange={(e) => { setFiltroNombre(e.target.value); setPagina(1) }}
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
                onChange={(e) => { setFiltroTipo(e.target.value); setPagina(1) }}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtCorto}>
          <Field label="Records Per Page">
            {(id) => (
              <Select
                id={id}
                value={String(porPagina)}
                onChange={(e) => { setPorPagina(Number(e.target.value)); setPagina(1) }}
              >
                {REGISTROS_POR_PAGINA.map((n) => (
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
            <Th field="name" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>Name</Th>
            <Th field="type" orden={orden} onOrdenar={alternar} style={{ width: 80 }}>Type</Th>
            <Th field="ttl" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>TTL</Th>
            <Th field="data" orden={orden} onOrdenar={alternar}>Data</Th>
            {/* The actions column reserved 230 px with three labels inside;
                with icons 120 is enough and the 110 left over go to the data,
                which is what the table is about. */}
            <th style={{ width: 120 }} />
          </>
        }
      >
        {enPagina.length === 0 ? (
          <tr>
            <td colSpan={6} className={tbl.sinFilas}>
              No Record Found
            </td>
          </tr>
        ) : (
          enPagina.map((r, i) => {
            const actions = accionesDeFila(zoneInfo.type, r.type)
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
                  <CeldaDatos record={r} notifyFailedFor={zoneInfo.notifyFailedFor} />
                </td>
                <td className={tbl.celdaAcciones}>
                  {!actions.ocultas && (
                    <div className={tbl.actions}>
                      <AccionFila
                        icono="editar"
                        name="Edit Record"
                        disabled={!p.canModify || busy}
                        onClick={() => p.onEditarRegistro(zoneInfo, r, records)}
                      />
                      <AccionFila
                        icono="energia"
                        name={r.disabled ? 'Enable Record' : 'Disable Record'}
                        disabled={actions.editingOnly || !p.canModify || busy}
                        onClick={() => cambiarEstado(r, !r.disabled)}
                      />
                      {/* Delete, inside the menu: the same rule as in the zone
                          list. */}
                      <Menu etiqueta={`Actions for ${nombreRelativo(r.name, zone)} ${r.type}`}>
                        {(cerrar) => (
                          <button
                            type="button"
                            disabled={actions.editingOnly || !p.canDelete || busy}
                            onClick={() => { cerrar(); borrarRegistro(r) }}
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
