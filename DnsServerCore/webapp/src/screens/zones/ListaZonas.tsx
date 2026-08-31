import { useCallback, useEffect, useRef, useState } from 'react'
import {
  deleteZone,
  deleteZones,
  disableZone,
  enableZone,
  estadoDeZona,
  etiquetaTipo,
  exportZone,
  listZones,
  nombreDeZona,
  resyncZone,
  TIPOS_ZONA,
  ZONAS_POR_PAGINA,
  type Zone,
} from '../../api/zones'
import { Button } from '../../ui/Button'
import { Field, Input, Select } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Tag, type TagTone } from '../../ui/Tag'
import { Menu, Separador } from '../../ui/Menu'
import { fechaMinuto as fecha } from '../../lib/fechas'
import { textoDeEstado, ventanaDePaginas } from '../../lib/paginacion'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Claves, Tabla } from '../../ui/Table'
import styles from './Zones.module.css'
import type { Aviso, Confirmacion } from './tipos'
import { Paginacion } from '../../ui/Paginacion'
import { avisoDeFallo } from '../../lib/aviso'

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
const IMPORTAR = ['Primary', 'Forwarder']
const EXPORTAR = ['Primary', 'Forwarder', 'Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Catalog']
const CONVERTIR = ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog']
const CLONAR = ['Primary', 'Forwarder']
/** `hideOptionsMenu` is false for the seven known types (zone.js:774-790). */
const CON_OPCIONES = [...TIPOS_ZONA] as string[]

export interface AccionesDeZona {
  onAbrir: (zone: string) => void
  onImportar: (zone: string) => void
  onConvertir: (zone: string, type: string) => void
  onClonar: (zone: string) => void
  onPermisos: (zone: string) => void
  onOpciones: (zone: string) => void
}

export interface ListaZonasProps extends AccionesDeZona {
  token: string | null
  node?: string
  canModify: boolean
  canDelete: boolean
  onAviso: (a: Aviso) => void
  onConfirmar: (c: Confirmacion) => void
  onAnadir: () => void
  /** Changes when something from outside (a modal) forces a re-read of the list. */
  refresco: number
}

export function ListaZonas({
  token,
  node = '',
  canModify,
  canDelete,
  onAviso,
  onConfirmar,
  onAnadir,
  onAbrir,
  onImportar,
  onConvertir,
  onClonar,
  onPermisos,
  onOpciones,
  refresco,
}: ListaZonasProps) {
  const [zonas, setZonas] = useState<Zone[]>([])
  const [pageNumber, setPageNumber] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalZones, setTotalZones] = useState(0)
  const [ocupado, setOcupado] = useState(false)
  const [marcadas, setMarcadas] = useState<string[]>([])

  // The filters are form state: they do not apply until "Go" is pressed,
  // just like upstream, where `refreshZones` reads them at that moment.
  const [filtroNombre, setFiltroNombre] = useState('')
  const [filtroTipo, setFiltroTipo] = useState('')
  const [porPagina, setPorPagina] = useState(10)
  const [campoPagina, setCampoPagina] = useState('1')

  const nombreRef = useRef<HTMLInputElement>(null)

  const cargar = useCallback(
    async (pagina: number) => {
      setOcupado(true)
      const r = await listZones(token, {
        filterName: filtroNombre,
        filterType: filtroTipo,
        pageNumber: pagina,
        zonesPerPage: porPagina,
        node,
      })
      setOcupado(false)

      if (r.kind !== 'ok') {
        // The server's message, not a guess about the network.
        onAviso(avisoDeFallo(r))
        return
      }

      const datos = r.data
      setZonas(datos.zones)
      setPageNumber(datos.pageNumber)
      setTotalPages(datos.totalPages)
      setTotalZones(datos.totalZones)
      setCampoPagina(String(datos.pageNumber))
      // `chkZonesTableCheckAll` is unchecked on every refresh (zone.js:938).
      setMarcadas([])
      nombreRef.current?.focus()
    },
    [token, node, filtroNombre, filtroTipo, porPagina, onAviso],
  )

  /*
  On mount and when something from outside asks for a re-read. The filters do
  NOT trigger a reload on their own: "Go" has to be pressed, just like upstream,
  where `refreshZones` reads them at that moment. That is why `cargar` goes by
  ref and not in the dependencies: were it there, typing in the filter would
  reload the list.
  */
  const cargarRef = useRef(cargar)
  useEffect(() => {
    cargarRef.current = cargar
  }, [cargar])
  useEffect(() => {
    void cargarRef.current(1)
  }, [refresco])

  function irA(pagina: number) {
    void cargar(pagina)
  }

  function aplicarFiltros() {
    const n = Number(campoPagina)
    void cargar(campoPagina === '' || Number.isNaN(n) ? 1 : n)
  }

  /** Runs a mutation and refreshes, with upstream's literal alert. */
  async function mutar(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
  ) {
    setOcupado(true)
    const outcome = await fn()
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    await cargar(pageNumber)
    onAviso(exito)
  }

  function habilitar(z: Zone) {
    const nombre = z.name === '' ? '.' : z.name
    void mutar(() => enableZone(token, nombre, node), {
      type: 'success',
      title: 'Zone Enabled!',
      text: `Zone '${nombre}' was enabled successfully.`,
    })
  }

  function deshabilitar(z: Zone) {
    const nombre = z.name === '' ? '.' : z.name
    onConfirmar({
      titulo: 'Disable Zone',
      texto: `Are you sure you want to disable the zone '${nombre}'?`,
      etiqueta: 'Disable',
      accion: () =>
        mutar(() => disableZone(token, nombre, node), {
          type: 'success',
          title: 'Zone Disabled!',
          text: `Zone '${nombre}' was disabled successfully.`,
        }),
    })
  }

  function borrar(z: Zone) {
    const nombre = z.name === '' ? '.' : z.name
    onConfirmar({
      titulo: 'Delete Zone',
      texto: `Are you sure you want to permanently delete the zone '${nombre}' and all its records?`,
      etiqueta: 'Delete',
      peligro: true,
      accion: () =>
        mutar(() => deleteZone(token, nombre, node), {
          type: 'success',
          title: 'Zone Deleted!',
          text: `Zone '${nombre}' was deleted successfully.`,
        }),
    })
  }

  function resincronizar(z: Zone) {
    const nombre = z.name === '' ? '.' : z.name
    // Two different texts: the secondary talks about AXFR and the rest about refresh.
    const texto =
      z.type === 'Secondary'
        ? `The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${nombre}' zone?`
        : `The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\n\nAre you sure you want to resync the '${nombre}' zone?`

    onConfirmar({
      titulo: 'Resync Zone',
      texto,
      etiqueta: 'Resync',
      accion: () =>
        mutar(() => resyncZone(token, nombre, node), {
          type: 'success',
          title: 'Resync Triggered!',
          text: `Zone '${nombre}' resync was triggered successfully. Please check the Logs for confirmation.`,
        }),
    })
  }

  async function exportar(z: Zone) {
    const nombre = z.name === '' ? '.' : z.name
    const r = await exportZone(token, nombre, node)
    if (!r.ok) return
    onAviso({ type: 'success', title: 'Zone Exported!', text: 'Zone file was exported successfully.' })
  }

  function borrarMarcadas() {
    if (marcadas.length === 0) {
      // A plain `alert()` in upstream, not a `showAlert` of the screen.
      onAviso({ type: 'warning', title: 'Missing!', text: 'Please select one or more zones to delete.' })
      return
    }

    const lista = zonas
      .filter((z) => marcadas.includes(z.name))
      .map((z) => (z.nameIdn == null ? (z.name === '' ? '.' : z.name) : `${z.nameIdn} (${z.name})`))

    onConfirmar({
      titulo: 'Delete Zones',
      texto: `Are you sure you want to permanently delete the following zones and all of their records?\n\n${lista.join('\n')}`,
      etiqueta: 'Delete',
      peligro: true,
      accion: async () => {
        setOcupado(true)
        const outcome = await deleteZones(token, marcadas, node)
        setOcupado(false)

        if (outcome.kind !== 'ok') {
          onAviso(avisoDeFallo(outcome))
          return
        }

        await cargar(pageNumber)

        const fallos = Object.keys(outcome.data.response.failed ?? {}).length
        if (fallos === 0) {
          onAviso({
            type: 'success',
            title: 'Zones Deleted!',
            text: 'All selected zones were deleted successfully.',
          })
        } else {
          const total = (outcome.data.response.deleted?.length ?? 0) + fallos
          onAviso({
            type: 'warning',
            title: 'Failed To Deleted!',
            text: `A total of ${fallos} zone(s) of the selected ${total} zone(s) failed to delete. Please check error logs for more details.`,
          })
        }
      },
    })
  }

  const primeraFila = (pageNumber - 1) * porPagina + 1
  const estado = textoDeEstado(primeraFila, zonas.length, totalZones, pageNumber, totalPages, 'zones')
  const pg = ventanaDePaginas(pageNumber, totalPages)
  const { filas: zonasVisibles, orden, alternar } = useOrden(CLAVES, zonas)

  const todasMarcadas = zonas.length > 0 && marcadas.length === zonas.length

  // The last page is asked for with -1: the server works it out itself.
  const paginacion = <Paginacion ventana={pg} actual={pageNumber} ultima={-1} onIr={irA} />

  return (
    <>
      <SectionHeader
        titulo="Zones"
        acciones={<><Button variant="primary" disabled={!canModify || ocupado} onClick={onAnadir}>
            Add Zone
          </Button>
          <Button variant="danger" disabled={!canDelete || ocupado} onClick={borrarMarcadas}>
            Delete Zones
          </Button></>}
      />

      <div className={styles.filt}>
        <div className={styles.filtAncho}>
          <Field label="Name">
            {(id) => (
              <Input
                id={id}
                ref={nombreRef}
                placeholder="abc or a* or *b* or a?c"
                value={filtroNombre}
                onChange={(e) => setFiltroNombre(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && aplicarFiltros()}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtMedio}>
          <Field label="Type">
            {(id) => (
              <Select id={id} value={filtroTipo} onChange={(e) => setFiltroTipo(e.target.value)}>
                <option value="" />
                {TIPOS_ZONA.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <div className={styles.filtCorto}>
          <Field label="Page Number">
            {(id) => (
              <Input
                id={id}
                mono
                value={campoPagina}
                onChange={(e) => setCampoPagina(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && aplicarFiltros()}
              />
            )}
          </Field>
        </div>
        <div className={styles.filtCorto}>
          <Field label="Zones Per Page">
            {(id) => (
              <Select id={id} value={String(porPagina)} onChange={(e) => setPorPagina(Number(e.target.value))}>
                {ZONAS_POR_PAGINA.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Button variant="primary" disabled={ocupado} onClick={aplicarFiltros}>
          Go
        </Button>
      </div>

      <div className={styles.count}>
        <span>{estado}</span>
        {paginacion}
      </div>

      <Tabla
        cabecera={
          <>
            {/* The checkbox is 18 px; it is pressed from anywhere in its cell. */}
            <th style={{ width: 38 }} className={tbl.celdaCheck}>
              <label>
                <input
                  type="checkbox"
                  aria-label="Select all zones"
                  checked={todasMarcadas}
                  onChange={(e) => setMarcadas(e.target.checked ? zonas.map((z) => z.name) : [])}
                />
              </label>
            </th>
            <th style={{ width: 34 }}>#</th>
            <Th campo="zone" orden={orden} onOrdenar={alternar}>Zone</Th>
            <Th campo="type" orden={orden} onOrdenar={alternar} style={{ width: 120 }}>Type</Th>
            <Th campo="dnssec" orden={orden} onOrdenar={alternar} style={{ width: 90 }}>DNSSEC</Th>
            <Th campo="status" orden={orden} onOrdenar={alternar} style={{ width: 120 }}>Status</Th>
            <Th
              campo="serial"
              orden={orden}
              onOrdenar={alternar}
              style={{ width: 110, textAlign: 'right' }}
            >
              Serial
            </Th>
            <Th campo="expiry" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>Expiry</Th>
            <Th campo="modified" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>
              Last Modified
            </Th>
            {/* The actions column reserved 230 px with three labels inside;
                with icons 120 is enough and the 110 left over go to the data,
                which is what the table is about. */}
            <th style={{ width: 120 }} />
          </>
        }
      >
        {zonasVisibles.length === 0 ? (
          <tr>
            <td colSpan={10} className={tbl.sinFilas}>
              No Zone Found
            </td>
          </tr>
        ) : (
          zonasVisibles.map((z, i) => (
            <FilaZona
              key={z.name}
              zona={z}
              indice={primeraFila + i}
              marcada={marcadas.includes(z.name)}
              ocupado={ocupado}
              canModify={canModify}
              canDelete={canDelete}
              onMarcar={(v) =>
                setMarcadas((m) => (v ? [...m, z.name] : m.filter((n) => n !== z.name)))
              }
              onAbrir={onAbrir}
              onHabilitar={habilitar}
              onDeshabilitar={deshabilitar}
              onBorrar={borrar}
              onResync={resincronizar}
              onImportar={onImportar}
              onExportar={exportar}
              onConvertir={onConvertir}
              onClonar={onClonar}
              onPermisos={onPermisos}
              onOpciones={onOpciones}
            />
          ))
        )}
      </Tabla>

      <div className={`${styles.count} ${styles.countPie}`}>
        <span>{estado}</span>
        {paginacion}
      </div>
    </>
  )
}

interface FilaProps {
  zona: Zone
  indice: number
  marcada: boolean
  ocupado: boolean
  canModify: boolean
  canDelete: boolean
  onMarcar: (v: boolean) => void
  onAbrir: (zone: string) => void
  onHabilitar: (z: Zone) => void
  onDeshabilitar: (z: Zone) => void
  onBorrar: (z: Zone) => void
  onResync: (z: Zone) => void
  onImportar: (zone: string) => void
  onExportar: (z: Zone) => void
  onConvertir: (zone: string, type: string) => void
  onClonar: (zone: string) => void
  onPermisos: (zone: string) => void
  onOpciones: (zone: string) => void
}

/*
What each column sorts by is THE TEXT YOU SEE, just like upstream
(`sortTable('tableZonesBody', 1..8)`). That is why `Serial` is read as a string
and not as a number: that way the order matches the old console's.
*/
const CLAVES: Claves<Zone> = {
  zone: (z) => nombreDeZona(z),
  type: (z) => etiquetaTipo(z.type),
  dnssec: (z) =>
    z.dnssecStatus === 'SignedWithNSEC' || z.dnssecStatus === 'SignedWithNSEC3'
      ? z.hasDnssecPrivateKeys
        ? 'Signed'
        : 'Signed, no keys'
      : 'Unsigned',
  status: (z) => estadoDeZona(z),
  serial: (z) => z.soaSerial,
  expiry: (z) => fecha(z.expiry),
  modified: (z) => fecha(z.lastModified),
}

function FilaZona(p: FilaProps) {
  const { zona: z } = p
  const nombre = z.name === '' ? '.' : z.name
  const estado = estadoDeZona(z)
  const firmada = z.dnssecStatus === 'SignedWithNSEC' || z.dnssecStatus === 'SignedWithNSEC3'

  const tonoEstado: TagTone =
    estado === 'Enabled'
      ? 'ok'
      : estado === 'Expired' || estado === 'Validation Failed'
        ? 'dan'
        : estado === 'Sync Failed' || estado === 'Notify Failed'
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
  const etiquetaCatalogo =
    z.catalog != null ? { texto: z.catalog, tono: 'neutral' as TagTone } : null

  return (
    <tr>
      <td className={tbl.celdaCheck}>
        <label>
          <input
            type="checkbox"
            aria-label={`Select ${nombre}`}
            checked={p.marcada}
            onChange={(e) => p.onMarcar(e.target.checked)}
          />
        </label>
      </td>
      <td className={`${styles.num} ${tbl.numero}`}>{p.indice}</td>
      {/* The monospacing goes on the CELL and the button inherits it: the
          shared class says `font-family: inherit` precisely for this, and putting
          it on the button depended on which module was emitted last. */}
      <td className={`${tbl.apilada} ${styles.celdaZona}`}>
        <button
          type="button"
          className={`${styles.enlaceZona} ${tbl.entidad}`}
          onClick={() => p.onAbrir(nombre)}
        >
          {nombreDeZona(z)}
        </button>
        {etiquetaCatalogo && (
          <div className={styles.tags}>
            <Tag tone={etiquetaCatalogo.tono}>{etiquetaCatalogo.texto}</Tag>
          </div>
        )}
      </td>
      {/* The type goes as text and not as a capsule: with Type, DNSSEC and
          Status all in capsules, three consecutive columns of pills read as a
          single smear and none of the three stood out. */}
      <td className={tbl.meta}>{etiquetaTipo(z.type)}</td>
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
        {!firmada ? (
          <Tag>Unsigned</Tag>
        ) : z.hasDnssecPrivateKeys ? (
          <Tag tone="info">Signed</Tag>
        ) : (
          <Tag>Signed, no keys</Tag>
        )}
      </td>
      <td>
        <Tag tone={tonoEstado}>{estado}</Tag>
      </td>
      <td className={styles.mono}>{z.soaSerial ?? ' '}</td>
      <td className={styles.mono}>{fecha(z.expiry)}</td>
      <td className={`${styles.mono} ${tbl.meta}`}>{fecha(z.lastModified)}</td>
      <td className={tbl.celdaAcciones}>
        <div className={tbl.acciones}>
          <AccionFila
            icono="settings"
            nombre="Zone Options"
            disabled={!p.canModify || p.ocupado || !CON_OPCIONES.includes(z.type)}
            onClick={() => p.onOpciones(nombre)}
          />
          {/* The same icon for both states: which one applies is said by the
              "Status" column, three columns to the left. */}
          <AccionFila
            icono="energia"
            nombre={z.disabled ? 'Enable Zone' : 'Disable Zone'}
            disabled={!p.canModify || p.ocupado}
            onClick={() => (z.disabled ? p.onHabilitar(z) : p.onDeshabilitar(z))}
          />
          <Menu etiqueta={`Actions for ${nombre}`}>
            {(cerrar) => (
              <>
                <button type="button" onClick={() => { cerrar(); p.onAbrir(nombre) }}>
                  Edit Zone
                </button>
                {RESYNC.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onResync(z) }}>
                    Resync
                  </button>
                )}
                {IMPORTAR.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onImportar(nombre) }}>
                    Import Zone
                  </button>
                )}
                {EXPORTAR.includes(z.type) && (
                  <button type="button" onClick={() => { cerrar(); void p.onExportar(z) }}>
                    Export Zone
                  </button>
                )}
                {CONVERTIR.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onConvertir(nombre, z.type) }}>
                    Convert Zone
                  </button>
                )}
                {CLONAR.includes(z.type) && (
                  <button type="button" disabled={!p.canModify} onClick={() => { cerrar(); p.onClonar(nombre) }}>
                    Clone Zone
                  </button>
                )}
                <button type="button" onClick={() => { cerrar(); p.onPermisos(nombre) }}>
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
                <Separador />
                <button type="button" data-variant="danger" disabled={!p.canDelete} onClick={() => { cerrar(); p.onBorrar(z) }}>
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
