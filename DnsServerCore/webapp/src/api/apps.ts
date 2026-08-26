import { apiRequest, type ApiOutcome } from './client'

/*
Los nueve endpoints de la familia `apps` (upstream/master:www/js/apps.js).

Formas verificadas con curl contra una instancia real (v15.x) el 2026-08-25, no
deducidas del código:

  1. `updateVersion`, `updateUrl` y `updateAvailable` son OPCIONALES en un app
     instalado. El servidor sólo los escribe si el app aparece en el catálogo de
     la tienda Y hay allí una versión compatible con este servidor
     (WebServiceAppsApi.cs:60-99). Un app instalado desde un zip propio nunca
     los trae. Además `apps/list` consulta el catálogo con un timeout de 5 s y,
     si falla, devuelve la lista SIN esos tres campos en ningún app.

  2. `installedApp` / `updatedApp` —lo que devuelven install, update,
     downloadAndInstall y downloadAndUpdate— tampoco los traen NUNCA: ese
     `WriteAppAsJson` se llama sin el catálogo. Upstream repinta la fila con esa
     respuesta, así que tras instalar el botón «Store Update» desaparece hasta
     la siguiente recarga de la lista. Aquí se recarga la lista y punto.

  3. `config/get` puede devolver `config: null`, no sólo cadena. Pasa en cuanto
     alguien guarda una config vacía: `config/set` con cadena vacía la guarda
     como null (WebServiceAppsApi.cs:494-496).

  4. `apps/uninstall` de un app que no existe responde `ok`, no error.
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
  /** Sólo cuando `installed` es true. */
  installedVersion?: string
  /** Sólo cuando `installed` es true. */
  updateAvailable?: boolean
}

/*
Las etiquetas de capacidad de cada clase del app, en el orden exacto de
`getAppRowHtml` (apps.js:80-104). Si no hay ninguna, upstream pone «Generic».
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
`node` es el nombre del nodo PRIMARIO del clúster: upstream lee siempre de él
para no mostrar una config que aún no se ha propagado (apps.js:460). Sin clúster
manda la cadena vacía y el servidor la ignora (DnsWebService.cs:2367-2370).
El nombre del primario sale de `sessionData.info.clusterNodes`, que esta consola
no expone todavía; llega con la fase del clúster.
*/
export function getAppConfig(
  token: string | null,
  name: string,
  node = '',
): Promise<ApiOutcome<{ response: { config: string | null } }>> {
  return apiRequest('apps/config/get', { token, body: { name, node } })
}

/*
POST, porque una config puede ser larga y no cabe en una query. El servidor lee
ambos parámetros con `QueryOrForm`, así que van los dos en el cuerpo.
Una config vacía se guarda como `null`: eso es del servidor, no de aquí.
*/
export function setAppConfig(
  token: string | null,
  name: string,
  config: string,
): Promise<ApiOutcome> {
  return apiRequest('apps/config/set', { token, method: 'POST', body: { name, config } })
}

/*
--- Subida del zip: pendiente de multipart en el cliente ---

`apps/install` y `apps/update` son las DOS únicas llamadas de esta familia que
no son una petición normal: son POST `multipart/form-data` con el zip
(apps.js:348 y apps.js:392). El servidor exige `HasFormContentType` y coge
`Form.Files[0]` (WebServiceAppsApi.cs:350-357 y 401-408), así que:

  - el NOMBRE del campo del fichero da igual (verificado con curl: subir el zip
    como `cualquierNombre` instala igual). Aquí se manda `fileAppZip` sólo por
    fidelidad a upstream;
  - `name` puede ir en la query, y así lo hace upstream;
  - son POST-only: por GET el servidor responde 404 (DnsWebService.cs:2183-2184).

`apiRequest` sólo sabe mandar `x-www-form-urlencoded` y no se toca desde aquí.
`buildUpload` deja armada la petición para el día que el cliente acepte un
`FormData`; ese día `installApp`/`updateApp` son una línea cada una.
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
