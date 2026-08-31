import { useCallback, useEffect, useRef, useState } from 'react'
import { listApps, type InstalledApp } from '../../api/apps'
import {
  ENTRIES_PER_PAGE,
  PROTOCOLOS,
  QCLASSES,
  RCODES,
  RESPONSE_TYPES,
  exportLogsCsv,
  queryLogs,
  type QueryLogEntry,
  type QueryLogPage,
  type QueryLogsParams,
} from '../../api/logs'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Input, Select } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { aIso, fechaHora } from './fechas'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import { Tabla } from '../../ui/Table'
import styles from './Logs.module.css'
import { ventanaDePaginas } from '../../lib/paginacion'
import { Paginacion } from '../../ui/Paginacion'

/*
Logs › Query Logs (logs.js:20-101 y 270-710).

Cinco comportamientos de upstream que son contrato y no preferencias:

  1. **Los dos avisos de «falta el app» NO dicen lo mismo.** El de «Query»
     termina en «…from the Apps section.»; el de «Export», no (logs.js:391 vs
     614). Uniformarlos sería cambiar un texto.
  2. **El orden de validación de «Query»**: primero el app, después la clase,
     después la fecha «From» y por último la «To». «Export» sólo valida las dos
     primeras: no mira las fechas.
  3. **«Live Update» no es un refresco: es un modo.** Al marcarlo, fija página 1
     y orden descendente, VACÍA «From» y «To», deshabilita esos cuatro
     controles y el botón «Query», y vuelve a consultar cada 2 s. Al
     desmarcarlo, RESETEA el formulario entero, no sólo esos campos.
  4. **«Logs Per Page» se recuerda en `localStorage`** con la clave
     `optQueryLogsEntriesPerPage`, y se relee en cada reset (logs.js:23-26 y
     63-65). El valor por defecto del formulario es 10, no los 25 del servidor.
  5. **La página «Last» se pide con `pageNumber=-1`**: el servidor devuelve la
     última. Comprobado contra una instancia v15.4.

Lo que NO está: el menú de cada fila («Query DNS Server», «Allow Domain» /
«Block Domain», logs.js:539-552). Sus tres acciones viven en otras pantallas
—DNS Client y Allowed/Blocked— y no hay forma de invocarlas desde aquí sin
tocar el Shell. Queda anotado como hueco de integración, no resuelto a medias.
*/

interface Aviso { type: AlertType; title: string; text: string }

export const CLAVE_ENTRIES_PER_PAGE = 'optQueryLogsEntriesPerPage'

interface Filtros {
  appName: string
  classPath: string
  pageNumber: string
  entriesPerPage: string
  descendingOrder: string
  start: string
  end: string
  clientIpAddress: string
  protocol: string
  responseType: string
  rcode: string
  qname: string
  qtype: string
  qclass: string
}

/** `resetQueryLogsForm` (logs.js:50). El formulario vuelve a sus valores por
 *  defecto y relee de `localStorage` cuántas entradas por página. */
function filtrosPorDefecto(appName: string, classPath: string): Filtros {
  let entriesPerPage: string = ENTRIES_PER_PAGE[0]
  try {
    const guardado = localStorage.getItem(CLAVE_ENTRIES_PER_PAGE)
    if (guardado != null) entriesPerPage = guardado
  } catch {
    /* Sin localStorage se usa el valor por defecto del formulario. */
  }

  return {
    appName,
    classPath,
    pageNumber: '1',
    entriesPerPage,
    descendingOrder: 'true',
    start: '',
    end: '',
    clientIpAddress: '',
    protocol: '',
    responseType: '',
    rcode: '',
    qname: '',
    qtype: '',
    qclass: '',
  }
}

/** Los apps que ofrecen query logs y, para cada uno, sus clases que lo ofrecen
 *  (logs.js:69-84 y 300-325). */
export function appsConQueryLogs(apps: InstalledApp[]): { name: string; classPaths: string[] }[] {
  return apps
    .map((a) => ({
      name: a.name,
      classPaths: a.dnsApps.filter((d) => d.isQueryLogs).map((d) => d.classPath),
    }))
    .filter((a) => a.classPaths.length > 0)
}

/** El fondo de una fila (logs.js:452-508): manda el RCODE y, dentro de él, el
 *  tipo de respuesta. Es la única señal de color de la tabla. */
export function claseFila(entry: QueryLogEntry): string {
  const bloqueada = ['blocked', 'upstreamblocked', 'upstreamblockedcached']
  const tipo = entry.responseType.toLowerCase()

  switch (entry.rcode.toLowerCase()) {
    case 'serverfailure':
      return styles.rServerFailure
    case 'nxdomain':
      return bloqueada.includes(tipo) ? styles.rBlocked : styles.rNxDomain
    case 'refused':
      return styles.rRefused
    default:
      if (tipo === 'authoritative') return styles.rAuthoritative
      if (tipo === 'recursive') return styles.rRecursive
      if (tipo === 'cached') return styles.rCached
      if (bloqueada.includes(tipo)) return styles.rBlocked
      return ''
  }
}

/** El texto del contador (logs.js:594-597). */
export function textoEstado(p: QueryLogPage): string {
  if (p.entries.length === 0) return '0 logs'
  const primera = p.entries[0].rowNumber
  const ultima = p.entries[p.entries.length - 1].rowNumber
  return `${primera}-${ultima} (${p.entries.length}) of ${p.totalEntries} logs (page ${p.pageNumber} of ${p.totalPages})`
}

/*
Las diez páginas centradas en la actual. Era una copia letra por letra de
`lib/paginacion.ts` —aquella citaba `zone.js:880-905` y ésta `logs.js:571-586`,
dos sitios de upstream que hacen lo mismo—, con sus propias pruebas. Se conserva
el nombre porque las pruebas de esta pantalla lo usan.
*/
export function rangoPaginas(pageNumber: number, totalPages: number): number[] {
  return ventanaDePaginas(pageNumber, totalPages).paginas
}

export interface QueryLogsProps {
  token: string | null
  node?: string
}

export function QueryLogs({ token, node = '' }: QueryLogsProps) {
  const [apps, setApps] = useState<{ name: string; classPaths: string[] }[] | null>(null)
  const [f, setF] = useState<Filtros>(() => filtrosPorDefecto('', ''))
  const [pagina, setPagina] = useState<QueryLogPage | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [live, setLive] = useState(false)

  const desde = useRef<HTMLInputElement>(null)
  const hasta = useRef<HTMLInputElement>(null)
  // El desplegable es `ui/Select`, así que lo que se enfoca es su disparador.
  const appRef = useRef<HTMLButtonElement>(null)
  const claseRef = useRef<HTMLButtonElement>(null)
  /* El bucle de «Live Update» y las validaciones leen SIEMPRE los filtros
     vigentes, pero re-armar el temporizador cada vez que se teclea en un campo
     lo reiniciaría. De ahí la referencia, sincronizada tras cada commit. */
  const filtrosRef = useRef(f)
  useEffect(() => {
    filtrosRef.current = f
  }, [f])

  useEffect(() => {
    let vivo = true
    void (async () => {
      const outcome = await listApps(token)
      if (!vivo) return
      if (outcome.kind !== 'ok') {
        /*
        Sin esto, un fallo aquí dejaba el desplegable de «Source App Name» a
        «—», que es lo mismo que enseña un servidor sin ninguna app de registro
        instalada. Y de ahí no se sale: sin app no hay consulta que hacer, así
        que la pantalla quedaba muerta sin decir por qué.
        */
        setApps([])
        setAviso({
          type: 'danger',
          title: 'Error!',
          text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
        })
        return
      }
      const lista = appsConQueryLogs(outcome.data.response.apps ?? [])
      setApps(lista)
      const primero = lista[0]
      setF(filtrosPorDefecto(primero?.name ?? '', primero?.classPaths[0] ?? ''))
    })()
    return () => {
      vivo = false
    }
  }, [token])

  const clasesDelApp = apps?.find((a) => a.name === f.appName)?.classPaths ?? []

  const parametros = useCallback((filtros: Filtros, pageNumber: string): QueryLogsParams => {
    // logs.js:405 — menos de 1 entrada por página cae a 10.
    const n = Number(filtros.entriesPerPage)
    const entriesPerPage = String(n < 1 || Number.isNaN(n) ? 10 : n)

    return {
      name: filtros.appName,
      classPath: filtros.classPath,
      pageNumber,
      entriesPerPage,
      descendingOrder: filtros.descendingOrder,
      start: aIso(filtros.start),
      end: aIso(filtros.end),
      clientIpAddress: filtros.clientIpAddress,
      protocol: filtros.protocol,
      responseType: filtros.responseType,
      rcode: filtros.rcode,
      qname: filtros.qname,
      qtype: filtros.qtype,
      qclass: filtros.qclass,
      node,
    }
  }, [node])

  const consultar = useCallback(
    async (pageNumber: string, enVivo: boolean) => {
      const filtros = filtrosRef.current

      // logs.js:389-401 — el app y la clase, en ese orden.
      if (filtros.appName === '') {
        setAviso({
          type: 'warning',
          title: 'Missing!',
          text: "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature from the Apps section.",
        })
        appRef.current?.focus()
        return
      }
      if (filtros.classPath === '') {
        setAviso({
          type: 'warning',
          title: 'Missing!',
          text: 'Please select a Class Path to query logs.',
        })
        claseRef.current?.focus()
        return
      }

      // logs.js:407-424 — «From» antes que «To», y sólo si el navegador dice
      // que lo tecleado no es una fecha.
      if (desde.current?.validity.badInput === true) {
        setAviso({
          type: 'warning',
          title: 'Missing!',
          text: "Please enter correct date and time for 'From' field.",
        })
        desde.current.focus()
        return
      }
      if (hasta.current?.validity.badInput === true) {
        setAviso({
          type: 'warning',
          title: 'Missing!',
          text: "Please enter correct date and time for 'To' field.",
        })
        hasta.current.focus()
        return
      }

      if (!enVivo) setOcupado(true)
      const outcome = await queryLogs(token, parametros(filtros, pageNumber))
      if (!enVivo) setOcupado(false)

      if (outcome.kind !== 'ok') {
        if (!enVivo) {
          setAviso({
            type: 'danger',
            title: 'Error!',
            text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
          })
        }
        return
      }

      setPagina(outcome.data.response)
    },
    [token, parametros],
  )

  const consultarRef = useRef(consultar)
  useEffect(() => {
    consultarRef.current = consultar
  }, [consultar])

  /* logs.js:610 — mientras «Live Update» esté marcado, se repite cada 2 s. */
  useEffect(() => {
    if (!live) return
    let cancelado = false
    let timer: ReturnType<typeof setTimeout> | undefined

    async function ciclo() {
      await consultarRef.current('1', true)
      if (cancelado) return
      timer = setTimeout(() => void ciclo(), 2000)
    }
    void ciclo()

    return () => {
      cancelado = true
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [live])

  function set(parcial: Partial<Filtros>) {
    setF((prev) => ({ ...prev, ...parcial }))
  }

  function cambiarApp(name: string) {
    // logs.js:21 — al cambiar de app se recargan sus clases y se toma la primera.
    const clases = apps?.find((a) => a.name === name)?.classPaths ?? []
    set({ appName: name, classPath: clases[0] ?? '' })
  }

  function reiniciar() {
    const primero = apps?.[0]
    setF(filtrosPorDefecto(primero?.name ?? '', primero?.classPaths[0] ?? ''))
  }

  function alternarLive(marcado: boolean) {
    if (marcado) {
      // logs.js:34-42 — fija página y orden, y vacía el rango de fechas.
      set({ pageNumber: '1', descendingOrder: 'true', start: '', end: '' })
      setLive(true)
      return
    }
    setLive(false)
    reiniciar()
  }

  async function exportar() {
    // logs.js:612-625 — el aviso del app NO lleva «from the Apps section.» y
    // aquí no se comprueban las fechas.
    if (f.appName === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature.",
      })
      appRef.current?.focus()
      return
    }
    if (f.classPath === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: 'Please select a Class Path to query logs.',
      })
      claseRef.current?.focus()
      return
    }

    setOcupado(true)
    await exportLogsCsv(token, parametros(f, f.pageNumber))
    setOcupado(false)
  }

  function guardarEntradasPorPagina(valor: string) {
    set({ entriesPerPage: valor })
    try {
      localStorage.setItem(CLAVE_ENTRIES_PER_PAGE, valor)
    } catch {
      /* Sin localStorage no se recuerda; el filtro sigue funcionando. */
    }
  }

  if (apps == null) return <Loading />


  return (
    <div className={styles.wrap}>
      <SectionHeader
        seccion="Logs"
        titulo="Query Logs"
        etiquetas={f.appName !== '' ? <Tag>app: {f.appName}</Tag> : undefined}
        acciones={<>
          <label className={styles.check}>
            <input
              type="checkbox"
              checked={live}
              onChange={(e) => alternarLive(e.target.checked)}
            />
            <span>Live Update</span>
          </label>
          <Button
            variant="primary"
            disabled={ocupado || live}
            onClick={() => void consultar(f.pageNumber, false)}
          >
            Query
          </Button>
          <Button disabled={ocupado} onClick={() => void exportar()}>
            Export
          </Button>
          <Button onClick={reiniciar}>Reset</Button>
        </>}
      />

      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}

      <div className={styles.fs}>
        <h3 className={styles.fsTitle}>Filters</h3>
        <div className={styles.fsIn}>
          <div className={styles.frow}>
            <div className={styles.frowLabel}>Source</div>
            <div className={styles.frowCtl}>
              <div className={styles.campo} style={{ width: 220 }}>
                <label htmlFor="ql-appName">App Name</label>
                <Select
                  id="ql-appName"
                  ref={appRef}
                  value={f.appName}
                  onChange={(e) => cambiarApp(e.target.value)}
                >
                  {apps.map((a) => (
                    <option key={a.name} value={a.name}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              </div>
              <div className={styles.campo} style={{ width: 220 }}>
                <label htmlFor="ql-classPath">Class Path</label>
                <Select
                  id="ql-classPath"
                  ref={claseRef}
                  value={f.classPath}
                  onChange={(e) => set({ classPath: e.target.value })}
                >
                  {clasesDelApp.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
          </div>

          <div className={styles.frow}>
            <div className={styles.frowLabel}>Period</div>
            <div className={styles.frowCtl}>
              <div className={styles.campo} style={{ width: 200 }}>
                <label htmlFor="ql-start">From</label>
                <Input
                  id="ql-start"
                  ref={desde}
                  type="datetime-local"
                  disabled={live}
                  value={f.start}
                  onChange={(e) => set({ start: e.target.value })}
                />
              </div>
              <div className={styles.campo} style={{ width: 200 }}>
                <label htmlFor="ql-end">To</label>
                <Input
                  id="ql-end"
                  ref={hasta}
                  type="datetime-local"
                  disabled={live}
                  value={f.end}
                  onChange={(e) => set({ end: e.target.value })}
                />
              </div>
              <div className={styles.campo} style={{ width: 140 }}>
                <label htmlFor="ql-order">Order</label>
                <Select
                  id="ql-order"
                  disabled={live}
                  value={f.descendingOrder}
                  onChange={(e) => set({ descendingOrder: e.target.value })}
                >
                  <option value="false">Ascending</option>
                  <option value="true">Descending</option>
                </Select>
              </div>
            </div>
          </div>

          <div className={styles.frow}>
            <div className={styles.frowLabel}>Query</div>
            <div className={styles.frowCtl}>
              <div className={styles.campo} style={{ width: 260 }}>
                <label htmlFor="ql-qname">Domain</label>
                <Input
                  id="ql-qname"
                  mono
                  placeholder="example.com or *.com"
                  value={f.qname}
                  onChange={(e) => set({ qname: e.target.value })}
                />
              </div>
              <div className={styles.campo} style={{ width: 130 }}>
                <label htmlFor="ql-qtype">Type</label>
                <Input
                  id="ql-qtype"
                  placeholder="A, AAAA, etc."
                  value={f.qtype}
                  onChange={(e) => set({ qtype: e.target.value })}
                />
              </div>
              <div className={styles.campo} style={{ width: 110 }}>
                <label htmlFor="ql-qclass">Class</label>
                <Select
                  id="ql-qclass"
                  value={f.qclass}
                  onChange={(e) => set({ qclass: e.target.value })}
                >
                  {QCLASSES.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </Select>
              </div>
              <div className={styles.campo} style={{ width: 180 }}>
                <label htmlFor="ql-clientIpAddress">Client IP Address</label>
                <Input
                  id="ql-clientIpAddress"
                  mono
                  value={f.clientIpAddress}
                  onChange={(e) => set({ clientIpAddress: e.target.value })}
                />
              </div>
            </div>
          </div>

          <div className={styles.frow}>
            <div className={styles.frowLabel}>Response</div>
            <div className={styles.frowCtl}>
              <div className={styles.campo} style={{ width: 150 }}>
                <label htmlFor="ql-protocol">Protocol</label>
                <Select
                  id="ql-protocol"
                  value={f.protocol}
                  onChange={(e) => set({ protocol: e.target.value })}
                >
                  {PROTOCOLOS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className={styles.campo} style={{ width: 200 }}>
                <label htmlFor="ql-responseType">Response Type</label>
                <Select
                  id="ql-responseType"
                  value={f.responseType}
                  onChange={(e) => set({ responseType: e.target.value })}
                >
                  {RESPONSE_TYPES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className={styles.campo} style={{ width: 160 }}>
                <label htmlFor="ql-rcode">RCODE</label>
                <Select
                  id="ql-rcode"
                  value={f.rcode}
                  onChange={(e) => set({ rcode: e.target.value })}
                >
                  {RCODES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className={styles.campo} style={{ width: 110 }}>
                <label htmlFor="ql-pageNumber">Page Number</label>
                <Input
                  id="ql-pageNumber"
                  type="number"
                  disabled={live}
                  value={f.pageNumber}
                  onChange={(e) => set({ pageNumber: e.target.value })}
                />
              </div>
              <div className={styles.campo} style={{ width: 130 }}>
                <label htmlFor="ql-entriesPerPage">Logs Per Page</label>
                <Select
                  id="ql-entriesPerPage"
                  value={f.entriesPerPage}
                  onChange={(e) => guardarEntradasPorPagina(e.target.value)}
                >
                  {ENTRIES_PER_PAGE.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
          </div>
        </div>
      </div>

      {pagina != null && (
        <>
          <div className={styles.count}>
            <span>{textoEstado(pagina)}</span>
            {/* logs.js:589 — «Last» se pide con -1; lo resuelve el servidor. */}
            <Paginacion
              ventana={ventanaDePaginas(pagina.pageNumber, pagina.totalPages)}
              actual={pagina.pageNumber}
              ultima={-1}
              onIr={(n) => void consultar(String(n), false)}
            />
          </div>

          <Tabla
            cabecera={
              <>
                <th>#</th>
                <th>Timestamp</th>
                <th>Client IP Address</th>
                <th>Protocol</th>
                <th>Response Type</th>
                <th>RCODE</th>
                <th>Domain</th>
                <th>Type</th>
                <th>Class</th>
                <th>Answer</th>
              </>
            }
          >
            {pagina.entries.map((e) => (
              <tr key={e.rowNumber} className={claseFila(e)}>
                <td className={styles.mono}>{e.rowNumber}</td>
                <td className={`${styles.mono} ${styles.nowrap}`}>{fechaHora(e.timestamp)}</td>
                <td className={`${styles.mono} ${styles.romper}`}>{e.clientIpAddress}</td>
                <td>{e.protocol}</td>
                <td>
                  {e.responseType}
                  {e.responseRtt != null && (
                    <div className={styles.rtt}>({e.responseRtt.toFixed(2)} ms)</div>
                  )}
                </td>
                <td>{e.rcode}</td>
                {/* logs.js:518 — la raíz se escribe con un punto. */}
                <td className={`${styles.mono} ${styles.romper}`}>
                  {e.qname === '' ? '.' : (e.qname ?? '')}
                </td>
                <td>{e.qtype ?? ''}</td>
                <td>{e.qclass ?? ''}</td>
                <td className={`${styles.mono} ${styles.romper}`}>{e.answer ?? ''}</td>
              </tr>
            ))}
          </Tabla>

          <div className={styles.count}>
            <span>{textoEstado(pagina)}</span>
          </div>
        </>
      )}
    </div>
  )
}
