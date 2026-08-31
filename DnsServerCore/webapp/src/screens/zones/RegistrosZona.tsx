import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  cuerpoBorrado,
  cuerpoCambioDeEstado,
  deleteRecord,
  getRecords,
  updateRecord,
  zonaTienePistaSvcbAuto,
  type Registro,
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
import { fechaMinuto as fecha } from '../../lib/fechas'
import { Menu, Separador } from '../../ui/Menu'
import { filtrar } from './filtro'
import { textoDeEstado, ventanaDePaginas } from './paginacion'
import { accionesDeFila, celdasDeRegistro, nombreRelativo, ocultarDnssec, type Celda } from './registro-vista'
import { cabeceraDeZona, estaFirmada, guardarOcultarDnssec, leerOcultarDnssec } from './vista-zona'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty, Loading } from '../../ui/Empty'
import { Chip, Tag } from '../../ui/Tag'
import pag from '../../ui/Pagination.module.css'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Claves } from '../../ui/Table'
import styles from './Zones.module.css'
import { Icono } from '../../ui/Icono'
import type { Aviso, Confirmacion } from './tipos'

/*
Los registros de una zona. Réplica de `showEditZone` (zone.js:3079) y
`showEditZonePage` (3500).

**Aquí la paginación es del cliente**, al revés que en la lista de zonas:
`zones/records/get` no pagina, trae la zona entera y upstream la corta en el
navegador. Si esto se hiciera con la paginación por defecto de una librería de
tablas, la lista de zonas se rompería y ésta no, o al revés; por eso las dos
están escritas a mano y separadas.
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
  onConfirmar: (c: Confirmacion) => void
  onAnadirRegistro: (zona: ZonaDeRegistros, registros: Registro[]) => void
  onEditarRegistro: (zona: ZonaDeRegistros, registro: Registro, registros: Registro[]) => void
  onImportar: (zone: string) => void
  onConvertir: (zone: string, type: string) => void
  onClonar: (zone: string) => void
  onPermisos: (zone: string) => void
  onOpciones: (zone: string) => void
  onFirmar: (zone: string) => void
  onDesfirmar: (zone: string) => void
  onVerDs: (zone: string) => void
  onPropiedadesDnssec: (zone: string) => void
  /** Cambia cuando un modal externo obliga a releer la zona. */
  refresco: number
  /*
  El TTL de expiración que quedó en el modal de registro. NO es un capricho:
  `updateRecordState` lo lee del campo del modal en vez de la fila, así que
  deshabilitar un registro manda lo que haya quedado ahí de la última vez —o
  vacío si el modal no se ha abierto. Es un fallo de upstream y se replica; ver
  CONVENCIONES.md.
  */
  expiryTtlDelModal: string
}

/*
`sortTable('tableEditZoneBody', 0..4)` en upstream, que ordena por el texto de
la celda. «Data» se lee por sus celdas ya formateadas, que es lo que se ve.

La columna `#` de upstream también es ordenable y aquí no: ordenar por el número
de fila que la propia ordenación acaba de repartir no lleva a ningún sitio.
*/
function textoDeCelda(c: Celda): string {
  switch (c.clase) {
    case 'valor':
      return c.texto
    case 'pares':
      return c.pares.map((p) => `${p.etiqueta} ${p.valor}`).join(' ')
    case 'lineas':
      return c.lineas.join(' ')
    case 'tabla':
      return [c.cabeceras, ...c.filas].map((f) => f.join(' ')).join(' ')
  }
}

const CLAVES: Claves<Registro> = {
  name: (r) => r.name,
  type: (r) => r.type,
  ttl: (r) => r.ttl,
  data: (r) => celdasDeRegistro(r).map(textoDeCelda).join(' '),
}

export function RegistrosZona(p: RegistrosZonaProps) {
  const { zone, token, node = '', onAviso } = p

  const [zona, setZona] = useState<ZonaDeRegistros | null>(null)
  const [registros, setRegistros] = useState<Registro[]>([])
  const [cargando, setCargando] = useState(true)
  const [ocupado, setOcupado] = useState(false)
  const [ocultarDnssecRegs, setOcultarDnssecRegs] = useState(leerOcultarDnssec)

  const [filtroNombre, setFiltroNombre] = useState('')
  const [filtroTipo, setFiltroTipo] = useState('')
  const [porPagina, setPorPagina] = useState(10)
  const [pagina, setPagina] = useState(1)

  const cargar = useCallback(async () => {
    setCargando(true)
    const r = await getRecords(token, zone, node)
    setCargando(false)

    if (r == null) {
      onAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
      return
    }
    setZona(r.zone)
    setRegistros(r.records)
  }, [token, zone, node, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar, p.refresco])

  // El filtrado de DNSSEC es previo al filtro de nombre/tipo, igual que en
  // upstream: `editZoneRecords` ya llega recortado a `showEditZonePage`.
  const visibles = useMemo(() => {
    const firmada = estaFirmada(zona?.dnssecStatus)
    const base = ocultarDnssecRegs && firmada ? ocultarDnssec(registros) : registros
    return filtrar(base, { nombre: filtroNombre, tipo: filtroTipo }, zone)
  }, [registros, ocultarDnssecRegs, zona, filtroNombre, filtroTipo, zone])

  const { filas: ordenadas, orden, alternar } = useOrden(CLAVES, visibles)

  const totalPages = Math.max(1, Math.ceil(visibles.length / porPagina))
  const paginaActual = Math.min(Math.max(pagina, 1), totalPages)
  const inicio = (paginaActual - 1) * porPagina
  const enPagina = ordenadas.slice(inicio, inicio + porPagina)

  const cab = zona ? cabeceraDeZona(zona.type, zona.dnssecStatus) : null

  /** Ejecuta una mutación sobre un registro y recarga la zona entera. */
  async function mutarRegistro(fn: () => Promise<{ kind: string; message?: string }>, exito: Aviso) {
    setOcupado(true)
    const outcome = await fn()
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      onAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? (outcome.message ?? '') : 'Invalid token or session expired.',
      })
      return
    }
    await cargar()
    onAviso(exito)
  }

  function cambiarEstado(r: Registro, deshabilitar: boolean) {
    const nombre = r.name === '' ? '.' : r.name
    const pistas = zonaTienePistaSvcbAuto(registros, r.type === 'A', r.type === 'AAAA')
    const cuerpo = {
      ...cuerpoCambioDeEstado(zone, r, deshabilitar, pistas),
      expiryTtl: p.expiryTtlDelModal,
    }

    const ejecutar = () =>
      mutarRegistro(
        () => updateRecord(token, cuerpo, node),
        deshabilitar
          ? { type: 'success', title: 'Record Disabled!', text: 'Resource record was disabled successfully.' }
          : { type: 'success', title: 'Record Enabled!', text: 'Resource record was enabled successfully.' },
      )

    // Sólo deshabilitar pregunta; habilitar no (zone.js:6241).
    if (!deshabilitar) {
      void ejecutar()
      return
    }

    p.onConfirmar({
      titulo: 'Disable Record',
      texto: `Are you sure to disable the ${r.type} record '${nombre}'?`,
      etiqueta: 'Disable',
      accion: ejecutar,
    })
  }

  function borrarRegistro(r: Registro) {
    const nombre = r.name === '' ? '.' : r.name
    const pistas = zonaTienePistaSvcbAuto(registros, r.type === 'A', r.type === 'AAAA')
    const cuerpo = cuerpoBorrado(zone, r)
    if (r.type === 'A' || r.type === 'AAAA') cuerpo.updateSvcbHints = String(pistas)

    p.onConfirmar({
      titulo: 'Delete Record',
      texto: `Are you sure to permanently delete the ${r.type} record '${nombre}'?`,
      etiqueta: 'Delete',
      peligro: true,
      accion: () =>
        mutarRegistro(() => deleteRecord(token, cuerpo, node), {
          type: 'success',
          title: 'Record Deleted!',
          text: 'Resource record was deleted successfully.',
        }),
    })
  }

  /* ── Acciones sobre la zona entera ─────────────────────────────────── */

  async function mutarZona(fn: () => Promise<{ kind: string; message?: string }>, exito: Aviso, volver = false) {
    setOcupado(true)
    const outcome = await fn()
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      onAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? (outcome.message ?? '') : 'Invalid token or session expired.',
      })
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
      texto: `Are you sure you want to disable the zone '${zone}'?`,
      etiqueta: 'Disable',
      accion: () =>
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
      texto: `Are you sure you want to permanently delete the zone '${zone}' and all its records?`,
      etiqueta: 'Delete',
      peligro: true,
      accion: () =>
        mutarZona(
          () => deleteZone(token, zone, node),
          { type: 'success', title: 'Zone Deleted!', text: `Zone '${zone}' was deleted successfully.` },
          true,
        ),
    })
  }

  function resincronizar() {
    if (zona == null) return
    const texto =
      zona.type === 'Secondary'
        ? `The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${zone}' zone?`
        : `The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${zone}' zone?`

    p.onConfirmar({
      titulo: 'Resync Zone',
      texto,
      etiqueta: 'Resync',
      accion: () =>
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

  if (cargando && zona == null) {
    return <Loading>Loading zone…</Loading>
  }

  if (zona == null) {
    return (
      <Empty titulo="Unable to open the zone">Go back to the list and try again.</Empty>
    )
  }

  const estado = estadoDeZona(zona as unknown as Zone)
  const firmada = estaFirmada(zona.dnssecStatus)
  const texto = textoDeEstado(inicio + 1, enPagina.length, visibles.length, paginaActual, totalPages, 'records')
  const pg = ventanaDePaginas(paginaActual, totalPages)

  const paginacion = (
    <span className={pag.pg}>
      {pg.primera && (
        <button type="button" className={pag.pgb} aria-label="First" onClick={() => setPagina(1)}>
          <Icono nombre="primera" tam={14} />
        </button>
      )}
      {pg.anterior != null && (
        <button type="button" className={pag.pgb} aria-label="Previous" onClick={() => setPagina(pg.anterior!)}>
          <Icono nombre="chevronIzquierda" tam={14} />
        </button>
      )}
      {pg.paginas.map((n) => (
        <button
          key={n}
          type="button"
          className={pag.pgb}
          aria-current={n === paginaActual}
          onClick={() => setPagina(n)}
        >
          {n}
        </button>
      ))}
      {pg.siguiente != null && (
        <button type="button" className={pag.pgb} aria-label="Next" onClick={() => setPagina(pg.siguiente!)}>
          <Icono nombre="chevronDerecha" tam={14} />
        </button>
      )}
      {pg.ultima && (
        <button type="button" className={pag.pgb} aria-label="Last" onClick={() => setPagina(totalPages)}>
          <Icono nombre="ultima" tam={14} />
        </button>
      )}
    </span>
  )

  return (
    <>
      <SectionHeader
        seccion="Zones"
        onVolver={p.onVolver}
        titulo={zone === '.' ? '<root>' : zone}
        etiquetas={
          <>
            <Tag>{etiquetaTipo(zona.type)}</Tag>
            <Tag tone={estado === 'Enabled' ? 'ok' : 'neutral'}>{estado}</Tag>
            {firmada && (
              <Tag tone="info">DNSSEC</Tag>
            )}
            {zona.catalog != null && <Tag>{zona.catalog}</Tag>}
          </>
        }
        acciones={
          <>
            {cab?.anadirRegistro && (
              <Button
                variant="primary"
                disabled={!p.canModify || ocupado}
                onClick={() => p.onAnadirRegistro(zona, registros)}
              >
                Add Record
              </Button>
            )}
            {zona.disabled ? (
              <Button disabled={!p.canModify || ocupado} onClick={habilitarZona}>
                Enable Zone
              </Button>
            ) : (
              <Button disabled={!p.canModify || ocupado} onClick={deshabilitarZona}>
                Disable Zone
              </Button>
            )}
            <Button variant="danger" disabled={!p.canDelete || ocupado} onClick={borrarZona}>
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
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onConvertir(zone, zona.type) }}>
                      Convert Zone
                    </button>
                  )}
                  {cab?.clonar && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onClonar(zone) }}>
                      Clone Zone
                    </button>
                  )}
                  {cab?.opciones && (
                    <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onOpciones(zone) }}>
                      Zone Options
                    </button>
                  )}
                  {cab?.permisos && (
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
        <span>{texto}</span>
        {paginacion}
      </div>

      <div className={tbl.wrap}>
        <table className={tbl.tabla}>
          <thead>
            <tr>
              <th style={{ width: 34 }}>#</th>
              <Th campo="name" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>Name</Th>
              <Th campo="type" orden={orden} onOrdenar={alternar} style={{ width: 80 }}>Type</Th>
              <Th campo="ttl" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>TTL</Th>
              <Th campo="data" orden={orden} onOrdenar={alternar}>Data</Th>
              {/* La columna de acciones reservaba 230 px con tres rótulos
                  dentro; con iconos le bastan 120 y los 110 que sobran se los
                  queda el dato, que es de lo que va la tabla. */}
              <th style={{ width: 120 }} />
            </tr>
          </thead>
          <tbody>
            {enPagina.length === 0 ? (
              <tr>
                <td colSpan={6} className={tbl.sinFilas}>
                  No Record Found
                </td>
              </tr>
            ) : (
              enPagina.map((r, i) => {
                const acciones = accionesDeFila(zona.type, r.type)
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
                      <CeldaDatos registro={r} notifyFailedFor={zona.notifyFailedFor} />
                    </td>
                    <td className={tbl.celdaAcciones}>
                      {!acciones.ocultas && (
                        <div className={tbl.acciones}>
                          <AccionFila
                            icono="editar"
                            nombre="Edit Record"
                            disabled={!p.canModify || ocupado}
                            onClick={() => p.onEditarRegistro(zona, r, registros)}
                          />
                          <AccionFila
                            icono="energia"
                            nombre={r.disabled ? 'Enable Record' : 'Disable Record'}
                            disabled={acciones.soloEdicion || !p.canModify || ocupado}
                            onClick={() => cambiarEstado(r, !r.disabled)}
                          />
                          {/* Borrar, dentro del menú: la misma regla que en la
                              lista de zonas. */}
                          <Menu etiqueta={`Actions for ${nombreRelativo(r.name, zone)} ${r.type}`}>
                            {(cerrar) => (
                              <button
                                type="button"
                                disabled={acciones.soloEdicion || !p.canDelete || ocupado}
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
          </tbody>
        </table>
      </div>

      <div className={`${styles.count} ${styles.countPie}`}>
        <span>{texto}</span>
        {paginacion}
      </div>

      {/* La expiración de la zona secundaria, que upstream pinta junto al título. */}
      {'expiry' in zona && (zona as { expiry?: string }).expiry != null && (
        <div className={styles.meta}>Expiry: {fecha((zona as { expiry?: string }).expiry)}</div>
      )}
    </>
  )
}
