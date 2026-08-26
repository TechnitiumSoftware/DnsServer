import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'

/*
La familia `logs`: seis endpoints, todos en `logs.js` de upstream.

Cinco cosas que hay que saber antes de tocar esta pantalla:

  1. **`logs/download` NO devuelve JSON.** Con éxito responde `text/plain` y el
     fichero entero (`Content-Disposition: attachment`); con error responde
     `application/json` y la envoltura de siempre. Comprobado contra una
     instancia v15.4. Por eso NO puede ir por `apiRequest`, que hace `res.json()`
     y convertiría cualquier log en un fallo de red. Upstream lo pide con
     `isTextResponse: true` y, si lo que llega trae `status`, lo pinta
     formateado dentro del mismo `<pre>` del visor (logs.js:170-172): el error
     se lee como si fuera el contenido del fichero. Se replica.

  2. **El visor pide sólo los 2 primeros MB** (`limit=2`, que el servidor
     multiplica por 1024*1024 en `WebServiceLogsApi.cs:100`). El botón
     «Download» pide el fichero ENTERO: va sin `limit`.

  3. **`logs/download` y `logs/export` son descargas con token de un solo uso**,
     por `window.open`, porque el navegador tiene que recibir el
     `Content-Disposition`. Van por `openDownload` de `api/user.ts`.

  4. **`logs/list` devuelve el nombre SIN extensión** (`fileName` sale de
     `Path.GetFileNameWithoutExtension`) y el tamaño ya formateado como cadena
     (`"20.48 KB"`). El borrado se pide con ese mismo nombre, pero el parámetro
     se llama `log`, no `fileName`: los dos endpoints no comparten nombre de
     parámetro. Confundirlos da un 500.

  5. **`logs/query` valida en el servidor con `Enum.Parse`**: un `qtype` que no
     sea un tipo real responde `Requested value 'ZZZ' was not found.`. No hay
     validación previa en el cliente para ese campo, y no se le añade.

Permisos (`WebServiceLogsApi.cs`): `list`, `download`, `query` y `export` piden
`Logs.View`; `delete` y `deleteAll` piden `Logs.Delete`.
*/

export interface LogFile {
  /** Sin extensión: el servidor ya se la quita. */
  fileName: string
  /** Ya formateado por el servidor, p. ej. `"20.48 KB"`. */
  size: string
}

/** Una fila de `logs/query`. `responseRtt` se OMITE cuando no hay medida, y
 *  `qname`, `qtype`, `qclass` y `answer` llegan como `null` explícito cuando la
 *  entrada no tiene pregunta o no tiene respuesta (`WebServiceLogsApi.cs:221-234`). */
export interface QueryLogEntry {
  rowNumber: number
  timestamp: string
  clientIpAddress: string
  protocol: string
  responseType: string
  responseRtt?: number
  rcode: string
  qname: string | null
  qtype: string | null
  qclass: string | null
  answer: string | null
}

export interface QueryLogPage {
  pageNumber: number
  totalPages: number
  totalEntries: number
  entries: QueryLogEntry[]
}

/** Los filtros de la consulta, en el orden en que upstream los monta en la URL. */
export interface QueryLogsParams {
  name: string
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
  node?: string
}

/** `logs/list` (logs.js:112). Lista vacía si el servidor falla. */
export async function listLogFiles(token: string | null, node = ''): Promise<LogFile[]> {
  const outcome = await apiRequest<{ response: { logFiles: LogFile[] } }>('logs/list', {
    token,
    body: { node },
  })
  return outcome.kind === 'ok' ? (outcome.data.response.logFiles ?? []) : []
}

/*
`logs/download` para el VISOR (logs.js:161). No pasa por `apiRequest` porque la
respuesta buena no es JSON; ver el punto 1 de la cabecera. Se replica también
qué se pinta cuando el servidor responde un error: el JSON formateado, dentro
del mismo visor.
*/
export async function downloadLogText(
  token: string | null,
  fileName: string,
  node = '',
  limit = '2',
): Promise<string | null> {
  const query = new URLSearchParams({ fileName, limit, node })
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  let texto: string
  try {
    const res = await fetch(`api/logs/download?${query.toString()}`, { headers })
    texto = await res.text()
  } catch {
    return null
  }

  // logs.js:170 — `if (response.status != null) response = JSON.stringify(...)`.
  try {
    const parsed: unknown = JSON.parse(texto)
    if (parsed !== null && typeof parsed === 'object' && 'status' in parsed) {
      return JSON.stringify(parsed, null, 2)
    }
  } catch {
    /* No era JSON: es el log. */
  }
  return texto
}

/** El botón «Download» del visor (logs.js:186): fichero ENTERO, sin `limit`,
 *  con token de un solo uso y en una pestaña nueva.
 *
 *  Lleva `ts` —el rompe-cachés— porque upstream se lo añade aquí
 *  (`"&ts=" + (new Date().getTime())`). `logs/export` NO lo lleva. */
export function openLogDownload(
  token: string | null,
  fileName: string,
  node = '',
): Promise<{ ok: boolean; url?: string }> {
  return openDownload(token, 'logs/download', { fileName, node }, { ts: true })
}

/** `logs/delete` (logs.js:212). Ojo: el parámetro se llama `log`. */
export function deleteLog(token: string | null, log: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('logs/delete', { token, body: { log, node } })
}

export function deleteAllLogs(token: string | null, node = ''): Promise<ApiOutcome> {
  return apiRequest('logs/deleteAll', { token, body: { node } })
}

/** `logs/query` (logs.js:436). Devuelve el resultado sin envolver para que la
 *  pantalla pueda distinguir un error del servidor de una página vacía. */
export async function queryLogs(
  token: string | null,
  params: QueryLogsParams,
): Promise<ApiOutcome<{ response: QueryLogPage }>> {
  const body: Record<string, string> = { ...params, node: params.node ?? '' }
  return apiRequest<{ response: QueryLogPage }>('logs/query', { token, body })
}

/** `logs/export` (logs.js:678). Los mismos filtros que `query` MENOS los tres de
 *  paginación: `pageNumber`, `entriesPerPage` y `descendingOrder` no viajan.
 *  Y sin `ts`: de las seis descargas de la consola, sólo la copia de ajustes y
 *  `logs/download` lo llevan (verificado en main.js:3100, logs.js:196,
 *  zone.js:1322, other-zones.js:554 y 623). */
export function exportLogsCsv(
  token: string | null,
  params: QueryLogsParams,
): Promise<{ ok: boolean; url?: string }> {
  const { name, classPath, start, end, clientIpAddress, protocol, responseType, rcode, qname, qtype, qclass } = params
  return openDownload(token, 'logs/export', {
    name,
    classPath,
    start,
    end,
    clientIpAddress,
    protocol,
    responseType,
    rcode,
    qname,
    qtype,
    qclass,
    node: params.node ?? '',
  })
}

/*
Las opciones de los desplegables del formulario, con las etiquetas y los valores
literales de index.html:3300-3399. La primera opción de los cuatro filtros de
respuesta es la vacía y va seleccionada.
*/
export const ENTRIES_PER_PAGE = ['10', '25', '50', '100', '250', '500'] as const

export const PROTOCOLOS: { value: string; label: string }[] = [
  { value: '', label: '' },
  { value: 'Udp', label: 'UDP' },
  { value: 'Tcp', label: 'TCP' },
  { value: 'Tls', label: 'TLS' },
  { value: 'Https', label: 'HTTPS' },
  { value: 'Quic', label: 'QUIC' },
  { value: 'UdpProxy', label: 'UDP Proxy' },
  { value: 'TcpProxy', label: 'TCP Proxy' },
]

export const RESPONSE_TYPES: { value: string; label: string }[] = [
  { value: '', label: '' },
  { value: 'Authoritative', label: 'Authoritative' },
  { value: 'Recursive', label: 'Recursive' },
  { value: 'Cached', label: 'Cached' },
  { value: 'Blocked', label: 'Blocked' },
  { value: 'UpstreamBlocked', label: 'UpstreamBlocked' },
  { value: 'UpstreamBlockedCached', label: 'UpstreamBlockedCached' },
]

export const RCODES: { value: string; label: string }[] = [
  { value: '', label: '' },
  { value: 'NoError', label: 'No Error' },
  { value: 'FormatError', label: 'Format Error' },
  { value: 'ServerFailure', label: 'Server Failure' },
  { value: 'NxDomain', label: 'NX Domain' },
  { value: 'NotImplemented', label: 'Not Implemented' },
  { value: 'Refused', label: 'Refused' },
  { value: 'YXDomain', label: 'YX Domain' },
  { value: 'YXRRSet', label: 'YX RRSet' },
  { value: 'NXRRSet', label: 'NX RRSet' },
  { value: 'NotAuth', label: 'Not Auth' },
  { value: 'NotZone', label: 'Not Zone' },
]

export const QCLASSES = ['', 'IN', 'CS', 'CH', 'HS', 'NONE', 'ANY'] as const
