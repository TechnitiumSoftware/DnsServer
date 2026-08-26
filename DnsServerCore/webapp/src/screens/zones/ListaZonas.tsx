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
import { Menu } from './Menu'
import { fechaMinuto as fecha } from '../../lib/fechas'
import { textoDeEstado, ventanaDePaginas } from './paginacion'
import pag from '../../ui/Pagination.module.css'
import tbl from '../../ui/Table.module.css'
import { Th, useOrden, type Claves } from '../../ui/Table'
import styles from './Zones.module.css'
import { Icono } from '../../ui/Icono'
import type { Aviso, Confirmacion } from './tipos'

/*
La lista de zonas. Réplica de `refreshZones` (zone.js:649) y de las seis
acciones que cuelgan de cada fila.

Dos cosas del original que aquí se ven raras y son deliberadas:

  · **El botón «Delete Zones» borra lo marcado y usa el mismo endpoint** que el
    borrado de una sola, con el parámetro en plural. Cuando alguna falla, el
    aviso NO es un error: es un `warning` que cuenta cuántas fallaron.

  · **Qué acciones ofrece una fila depende del tipo de zona**, con cinco listas
    distintas que se solapan a medias (`showResyncMenu`, y los cuatro `switch`
    de Import / Export / Convert / Clone). No se uniforman.
*/

/** Los tipos que ofrecen cada acción, tal cual los enumera zone.js:760-880. */
const RESYNC = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']
const IMPORTAR = ['Primary', 'Forwarder']
const EXPORTAR = ['Primary', 'Forwarder', 'Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Catalog']
const CONVERTIR = ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog']
const CLONAR = ['Primary', 'Forwarder']
/** `hideOptionsMenu` es falso para los siete tipos conocidos (zone.js:774-790). */
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
  /** Cambia cuando algo de fuera (un modal) obliga a releer la lista. */
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

  // Los filtros son estado del formulario: no se aplican hasta pulsar «Go»,
  // igual que en upstream, donde `refreshZones` los lee en ese momento.
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

      if (r == null) {
        onAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }

      setZonas(r.zones)
      setPageNumber(r.pageNumber)
      setTotalPages(r.totalPages)
      setTotalZones(r.totalZones)
      setCampoPagina(String(r.pageNumber))
      // `chkZonesTableCheckAll` se desmarca en cada refresco (zone.js:938).
      setMarcadas([])
      nombreRef.current?.focus()
    },
    [token, node, filtroNombre, filtroTipo, porPagina, onAviso],
  )

  /*
  Al montar y cuando algo de fuera pide releer. Los filtros NO disparan recarga
  por sí solos: hay que pulsar «Go», igual que en upstream, donde `refreshZones`
  los lee en ese momento. Por eso `cargar` va por referencia y no en las
  dependencias: si estuviera, teclear en el filtro recargaría la lista.
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

  /** Ejecuta una mutación y refresca, con el aviso literal de upstream. */
  async function mutar(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
  ) {
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
    // Dos textos distintos: la secundaria habla de AXFR y el resto de refresco.
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
      // `alert()` sin más en upstream, no un `showAlert` de la pantalla.
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
          onAviso({
            type: 'danger',
            title: 'Error!',
            text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
          })
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

  const paginacion = (
    <span className={pag.pg}>
      {pg.primera && (
        <button type="button" className={pag.pgb} aria-label="First" onClick={() => irA(1)}>
          <Icono nombre="primera" tam={14} />
        </button>
      )}
      {pg.anterior != null && (
        <button type="button" className={pag.pgb} aria-label="Previous" onClick={() => irA(pg.anterior!)}>
          <Icono nombre="chevronIzquierda" tam={14} />
        </button>
      )}
      {pg.paginas.map((p) => (
        <button
          key={p}
          type="button"
          className={pag.pgb}
          aria-current={p === pageNumber}
          onClick={() => irA(p)}
        >
          {p}
        </button>
      ))}
      {pg.siguiente != null && (
        <button type="button" className={pag.pgb} aria-label="Next" onClick={() => irA(pg.siguiente!)}>
          <Icono nombre="chevronDerecha" tam={14} />
        </button>
      )}
      {/* La última página se pide con -1: el servidor la resuelve él. */}
      {pg.ultima && (
        <button type="button" className={pag.pgb} aria-label="Last" onClick={() => irA(-1)}>
          <Icono nombre="ultima" tam={14} />
        </button>
      )}
    </span>
  )

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
        <Button variant="primary" disabled={ocupado} onClick={aplicarFiltros} style={{ marginBottom: 1 }}>
          Go
        </Button>
      </div>

      <div className={styles.count}>
        <span>{estado}</span>
        {paginacion}
      </div>

      <div className={tbl.wrap}>
        <table className={tbl.tabla}>
          <thead>
            <tr>
              <th style={{ width: 30 }}>
                <input
                  type="checkbox"
                  aria-label="Select all zones"
                  checked={todasMarcadas}
                  onChange={(e) => setMarcadas(e.target.checked ? zonas.map((z) => z.name) : [])}
                />
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
              <th style={{ width: 230 }} />
            </tr>
          </thead>
          <tbody>
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
          </tbody>
        </table>
      </div>

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
Lo que se ordena en cada columna es EL TEXTO QUE SE VE, igual que upstream
(`sortTable('tableZonesBody', 1..8)`). Por eso `Serial` se lee como cadena y no
como número: así el orden coincide con el de la consola vieja.
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

  // El catálogo del que es miembro; y si ELLA es un catálogo, su propio nombre.
  const etiquetaCatalogo =
    z.catalog != null
      ? { texto: z.catalog, tono: 'neutral' as TagTone }
      : z.type === 'Catalog' || z.type === 'SecondaryCatalog'
        ? { texto: nombre, tono: 'info' as TagTone }
        : null

  return (
    <tr>
      <td>
        <input
          type="checkbox"
          aria-label={`Select ${nombre}`}
          checked={p.marcada}
          onChange={(e) => p.onMarcar(e.target.checked)}
        />
      </td>
      <td className={`${styles.num} ${tbl.numero}`}>{p.indice}</td>
      <td className={tbl.apilada}>
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
      {/* El tipo va en texto y no en cápsula: con Type, DNSSEC y Status en
          cápsula, tres columnas seguidas de píldoras se leían como una sola
          mancha y ninguna de las tres destacaba. */}
      <td className={tbl.meta}>{etiquetaTipo(z.type)}</td>
      <td>
        {/*
        Upstream deja la celda VACÍA cuando la zona no está firmada
        (zone.js:721-731), y una celda en blanco no dice «sin firmar»: dice «no
        lo sé» o «no ha cargado». Con 240 zonas paginadas de diez en diez,
        «cuáles me faltan por firmar» sólo se podía contestar desde la API.

        Los tres estados se dicen con tres textos distintos, no con el mismo
        texto en dos colores: sin claves privadas la zona está firmada pero este
        servidor no puede re-firmarla, que no es lo mismo que estar firmada.
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
      <td>
        <div className={tbl.acciones}>
          <Button
            size="sm"
            disabled={!p.canModify || p.ocupado || !CON_OPCIONES.includes(z.type)}
            onClick={() => p.onOpciones(nombre)}
          >
            Options
          </Button>
          {z.disabled ? (
            <Button
              size="sm"
              disabled={!p.canModify || p.ocupado}
              onClick={() => p.onHabilitar(z)}
            >
              Enable
            </Button>
          ) : (
            <Button
              size="sm"
              disabled={!p.canModify || p.ocupado}
              onClick={() => p.onDeshabilitar(z)}
            >
              Disable
            </Button>
          )}
          {/* Borrar está en la fila, no dentro del menú: en la pantalla de la
              zona —a un clic de aquí— también lo está, y la misma acción no
              puede costar un clic en un sitio y dos en el de al lado. */}
          <Button
            size="sm"
            variant="danger"
            disabled={!p.canDelete || p.ocupado}
            onClick={() => p.onBorrar(z)}
          >
            Delete
          </Button>
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
              </>
            )}
          </Menu>
        </div>
      </td>
    </tr>
  )
}
