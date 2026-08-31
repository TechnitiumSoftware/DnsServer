import { apiRequest, type ApiOutcome } from './client'

/*
The nine endpoints of the `apps` family (upstream/master:www/js/apps.js).

Shapes verified with curl against a real instance (v15.x) on 2026-08-25, not
deduced from the code:

  1. `updateVersion`, `updateUrl` and `updateAvailable` are OPTIONAL on an
     installed app. The server only writes them if the app appears in the store
     catalog AND there is a version there compatible with this server
     (WebServiceAppsApi.cs:60-99). An app installed from your own zip never
     brings them. On top of that, `apps/list` queries the catalog with a 5 s
     timeout and, if it fails, returns the list WITHOUT those three fields on any
     app.

  2. `installedApp` / `updatedApp` —what install, update, downloadAndInstall and
     downloadAndUpdate return— never bring them either: that `WriteAppAsJson` is
     called without the catalog. Upstream redraws the row with that response, so
     after installing, the "Store Update" button disappears until the next reload
     of the list. Here the list is reloaded and that is that.

  3. `config/get` can return `config: null`, not only a string. It happens as
     soon as someone saves an empty config: `config/set` with an empty string
     stores it as null (WebServiceAppsApi.cs:494-496).

  4. `apps/uninstall` of an app that does not exist answers `ok`, not an error.
*/

export interface DnsAppDetail {
  classPath: string
  description: string
  isAppRecordRequestHandler: boolean
  recordDataTemplate: string | null
  isRequestController: boolean
  isAuthoritativeRequestHandler: boolean
  isRequestBlockingHandler: boolean
  isQueryLogger: boolean
  isQueryLogs: boolean
  isPostProcessor: boolean
}

export interface InstalledApp {
  name: string
  description: string | null
  version: string
  updateVersion?: string
  updateUrl?: string
  updateAvailable?: boolean
  dnsApps: DnsAppDetail[]
}

export interface StoreApp {
  name: string
  description: string
  version: string
  url: string
  size: string
  installed: boolean
  /** Only when `installed` is true. */
  installedVersion?: string
  /** Only when `installed` is true. */
  updateAvailable?: boolean
}

/*
The capability labels of each of the app's classes, in the exact order of
`getAppRowHtml` (apps.js:80-104). If there is none, upstream puts "Generic".
*/
export function etiquetasDnsApp(d: DnsAppDetail): string[] {
  const labels: string[] = []
  if (d.isAppRecordRequestHandler) labels.push('APP Record')
  if (d.isRequestController) labels.push('Access Control')
  if (d.isAuthoritativeRequestHandler) labels.push('Authoritative')
  if (d.isRequestBlockingHandler) labels.push('Blocking')
  if (d.isQueryLogger) labels.push('Query Logger')
  if (d.isQueryLogs) labels.push('Query Logs')
  if (d.isPostProcessor) labels.push('Post Processor')
  return labels.length > 0 ? labels : ['Generic']
}

export function listApps(
  token: string | null,
  node = '',
): Promise<ApiOutcome<{ response: { apps: InstalledApp[] } }>> {
  return apiRequest('apps/list', { token, body: { node } })
}

export function listStoreApps(
  token: string | null,
): Promise<ApiOutcome<{ response: { storeApps: StoreApp[] } }>> {
  return apiRequest('apps/listStoreApps', { token })
}

export function downloadAndInstall(
  token: string | null,
  name: string,
  url: string,
): Promise<ApiOutcome<{ response: { installedApp: InstalledApp } }>> {
  return apiRequest('apps/downloadAndInstall', { token, body: { name, url } })
}

export function downloadAndUpdate(
  token: string | null,
  name: string,
  url: string,
): Promise<ApiOutcome<{ response: { updatedApp: InstalledApp } }>> {
  return apiRequest('apps/downloadAndUpdate', { token, body: { name, url } })
}

export function uninstallApp(token: string | null, name: string): Promise<ApiOutcome> {
  return apiRequest('apps/uninstall', { token, body: { name } })
}

/*
`node` is the name of the cluster's PRIMARY node: upstream always reads from it
so as not to show a config that has not propagated yet (apps.js:460). Without a
cluster it sends the empty string and the server ignores it
(DnsWebService.cs:2367-2370). The primary's name comes from
`sessionData.info.clusterNodes`, which this console does not expose yet; it
arrives with the cluster phase.
*/
export function getAppConfig(
  token: string | null,
  name: string,
  node = '',
): Promise<ApiOutcome<{ response: { config: string | null } }>> {
  return apiRequest('apps/config/get', { token, body: { name, node } })
}

/*
POST, because a config can be long and does not fit in a query. The server reads
both parameters with `QueryOrForm`, so both go in the body. An empty config is
stored as `null`: that is the server's doing, not ours.
*/
export function setAppConfig(
  token: string | null,
  name: string,
  config: string,
): Promise<ApiOutcome> {
  return apiRequest('apps/config/set', { token, method: 'POST', body: { name, config } })
}

/*
--- Zip upload: pending multipart support in the client ---

`apps/install` and `apps/update` are the ONLY TWO calls of this family that are
not an ordinary request: they are POST `multipart/form-data` with the zip
(apps.js:348 and apps.js:392). The server requires `HasFormContentType` and takes
`Form.Files[0]` (WebServiceAppsApi.cs:350-357 and 401-408), so:

  - the field NAME of the file does not matter (verified with curl: uploading the
    zip as `anyNameAtAll` installs just the same). `fileAppZip` is sent here only
    out of fidelity to upstream;
  - `name` may go in the query, and that is what upstream does;
  - they are POST-only: by GET the server answers 404 (DnsWebService.cs:2183-2184).

`apiRequest` only knows how to send `x-www-form-urlencoded` and is not touched
from here. `buildUpload` leaves the request built for the day the client accepts
a `FormData`; that day `installApp`/`updateApp` become one line each.
*/
export interface UploadRequest {
  path: string
  form: FormData
}

export function buildUpload(path: string, name: string, file: File): UploadRequest {
  const form = new FormData()
  form.append('fileAppZip', file)
  return { path: `${path}?${new URLSearchParams({ name }).toString()}`, form }
}


export function installApp(
  token: string | null,
  name: string,
  file: File,
): Promise<ApiOutcome<{ response: { installedApp: InstalledApp } }>> {
  const { path, form } = buildUpload('apps/install', name, file)
  return apiRequest(path, { token, form })
}

export function updateApp(
  token: string | null,
  name: string,
  file: File,
): Promise<ApiOutcome<{ response: { updatedApp: InstalledApp } }>> {
  const { path, form } = buildUpload('apps/update', name, file)
  return apiRequest(path, { token, form })
}
