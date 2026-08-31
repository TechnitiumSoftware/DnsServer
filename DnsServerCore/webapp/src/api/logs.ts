import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'
import { urlApi } from '../app/base'

/*
The `logs` family: six endpoints, all of them in upstream's `logs.js`.

Five things to know before touching this screen:

  1. **`logs/download` does NOT return JSON.** On success it answers `text/plain`
     and the whole file (`Content-Disposition: attachment`); on error it answers
     `application/json` and the usual envelope. Checked against a v15.4 instance.
     That is why it can NOT go through `apiRequest`, which does `res.json()` and
     would turn any log into a network failure. Upstream asks for it with
     `isTextResponse: true` and, if what arrives carries `status`, draws it
     formatted inside the viewer's own `<pre>` (logs.js:170-172): the error reads
     as if it were the file's content. That is replicated.

  2. **The viewer asks only for the first 2 MB** (`limit=2`, which the server
     multiplies by 1024*1024 in `WebServiceLogsApi.cs:100`). The "Download"
     button asks for the WHOLE file: it goes without `limit`.

  3. **`logs/download` and `logs/export` are downloads with a single-use token**,
     via `window.open`, because the browser has to receive the
     `Content-Disposition`. They go through `openDownload` in `api/user.ts`.

  4. **`logs/list` returns the name WITHOUT extension** (`fileName` comes from
     `Path.GetFileNameWithoutExtension`) and the size already formatted as a
     string (`"20.48 KB"`). The delete is asked for with that same name, but the
     parameter is called `log`, not `fileName`: the two endpoints do not share a
     parameter name. Mixing them up gives a 500.

  5. **`logs/query` validates on the server with `Enum.Parse`**: a `qtype` that
     is not a real type answers `Requested value 'ZZZ' was not found.`. There is
     no prior client-side validation for that field, and none is added.

Permissions (`WebServiceLogsApi.cs`): `list`, `download`, `query` and `export`
ask for `Logs.View`; `delete` and `deleteAll` ask for `Logs.Delete`.
*/

export interface LogFile {
  /** Without extension: the server already strips it. */
  fileName: string
  /** Already formatted by the server, e.g. `"20.48 KB"`. */
  size: string
}

/** A row of `logs/query`. `responseRtt` is OMITTED when there is no measurement,
 *  and `qname`, `qtype`, `qclass` and `answer` arrive as an explicit `null` when
 *  the entry has no question or no answer (`WebServiceLogsApi.cs:221-234`). */
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

/** The query's filters, in the order upstream builds them into the URL. */
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

/*
Returns the whole outcome, not a list.

It used to return `[]` when the server failed, and that looked prudent —"the
screen does not blow up if the request falls over". It was the opposite: an empty
list and a failure draw the same, so the screen said "No Log File Was Found" when
what had happened was that the call never arrived. That is worse than an error,
because nobody suspects a response that looks normal.

By returning the `ApiOutcome` —as the list screens already did, and those did
warn— the type forces the two apart, and the message the server sent is kept as
well, which is what upstream shows.
*/
/** `logs/list` (logs.js:112). */
export async function listLogFiles(
  token: string | null,
  node = '',
): Promise<ApiOutcome<LogFile[]>> {
  const outcome = await apiRequest<{ response: { logFiles: LogFile[] } }>('logs/list', {
    token,
    body: { node },
  })
  return outcome.kind === 'ok'
    ? { kind: 'ok', data: outcome.data.response.logFiles ?? [] }
    : outcome
}

/*
`logs/download` for the VIEWER (logs.js:161). It does not go through
`apiRequest` because the good response is not JSON; see point 1 of the header.
What is drawn when the server answers an error is replicated too: the formatted
JSON, inside the viewer itself.
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
    const res = await fetch(urlApi(`api/logs/download?${query.toString()}`), { headers })
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
    /* It was not JSON: it is the log. */
  }
  return texto
}

/** The viewer's "Download" button (logs.js:186): the WHOLE file, without
 *  `limit`, with a single-use token and in a new tab.
 *
 *  It carries `ts` —the cache-buster— because upstream adds it here
 *  (`"&ts=" + (new Date().getTime())`). `logs/export` does NOT carry it. */
export function openLogDownload(
  token: string | null,
  fileName: string,
  node = '',
): Promise<{ ok: boolean; url?: string }> {
  return openDownload(token, 'logs/download', { fileName, node }, { ts: true })
}

/** `logs/delete` (logs.js:212). Careful: the parameter is called `log`. */
export function deleteLog(token: string | null, log: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('logs/delete', { token, body: { log, node } })
}

export function deleteAllLogs(token: string | null, node = ''): Promise<ApiOutcome> {
  return apiRequest('logs/deleteAll', { token, body: { node } })
}

/** `logs/query` (logs.js:436). Returns the outcome unwrapped so the screen can
 *  tell a server error apart from an empty page. */
export async function queryLogs(
  token: string | null,
  params: QueryLogsParams,
): Promise<ApiOutcome<{ response: QueryLogPage }>> {
  const body: Record<string, string> = { ...params, node: params.node ?? '' }
  return apiRequest<{ response: QueryLogPage }>('logs/query', { token, body })
}

/** `logs/export` (logs.js:678). The same filters as `query` MINUS the three
 *  paging ones: `pageNumber`, `entriesPerPage` and `descendingOrder` do not
 *  travel. And without `ts`: of the console's six downloads, only the settings
 *  backup and `logs/download` carry it (verified in main.js:3100, logs.js:196,
 *  zone.js:1322, other-zones.js:554 and 623). */
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
The options of the form's dropdowns, with the labels and the literal values of
index.html:3300-3399. The first option of the four response filters is the empty
one and comes selected.
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
