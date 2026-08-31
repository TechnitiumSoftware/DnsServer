import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'

/*
Familia `zones`, parte de gestión de zonas: 15 endpoints. Los 4 de
`zones/records/*` viven en registros.ts y los 15 de DNSSEC en dnssec.ts. Entre
los tres suman los 34 de la fase 4.

DOS PAGINACIONES DISTINTAS, y esto es fácil de equivocar:

  · `zones/list` PAGINA EN EL SERVIDOR: se le mandan `pageNumber` y
    `zonesPerPage`, y devuelve `pageNumber`, `totalPages` y `totalZones`.
    Ojo: esos tres campos **sólo aparecen si mandas `pageNumber`**; sin él la
    respuesta trae únicamente `zones`.

  · `zones/records/get` NO pagina (ver registros.ts).

`node` es el nodo del clúster al que se dirige la petición
(`optZonesClusterNode`). Con una sola instancia va vacío, y así lo manda
upstream: la cadena `&node=` viaja igualmente en las 40 llamadas de zone.js.
*/

/*
Sospecha de todo campo opcional. Comprobado contra una v15.4 recién instalada:

  · `zones/list` NO devuelve los cinco que gobiernan el estado (`isExpired`,
    `validationFailed`, `syncFailed`, `expiry`) ni `nameIdn` salvo en zonas
    secundarias, caducadas o con nombre internacionalizado.

  · Y lo que menos se espera: **una zona Catalog o Forwarder omite
    `dnssecStatus` y `hasDnssecPrivateKeys`**, y la Catalog omite además
    `catalog`. Son tipos que no pueden firmarse, así que el servidor ni los
    escribe. Declararlos obligatorios miente sobre la mitad de la lista.
*/
export interface Zone {
  name: string
  type: string
  lastModified: string
  disabled: boolean
  soaSerial: number | null
  catalog?: string | null
  dnssecStatus?: string
  hasDnssecPrivateKeys?: boolean
  notifyFailed: boolean
  notifyFailedFor: string[]
  expiry?: string
  isExpired?: boolean
  validationFailed?: boolean
  syncFailed?: boolean
  /** Nombre internacionalizado; sólo en zonas con caracteres no ASCII. */
  nameIdn?: string
  /** Sólo en zonas internas del servidor: no se pueden borrar ni editar. */
  internal?: boolean
}

/**
 * El estado que se pinta en la fila, con la prioridad EXACTA de
 * `refreshZones` (zone.js:733-745). No es alfabética ni por gravedad: es la
 * cadena de `else if` de upstream y el orden importa — una zona caducada y con
 * notificación fallida dice «Expired», no «Notify Failed».
 */
export type EstadoZona = 'Disabled' | 'Expired' | 'Validation Failed' | 'Sync Failed' | 'Notify Failed' | 'Enabled'

export function estadoDeZona(z: Zone): EstadoZona {
  if (z.disabled) return 'Disabled'
  if (z.isExpired) return 'Expired'
  if (z.validationFailed) return 'Validation Failed'
  if (z.syncFailed) return 'Sync Failed'
  if (z.notifyFailed) return 'Notify Failed'
  return 'Enabled'
}

/** El texto del tipo: sólo los dos «Secondary…» se parten en dos palabras. */
export function etiquetaTipo(type: string): string {
  if (type === 'SecondaryForwarder') return 'Secondary Forwarder'
  if (type === 'SecondaryCatalog') return 'Secondary Catalog'
  return type
}

/** El nombre que se pinta: la raíz es `<root>` y un IDN lleva los dos. */
export function nombreDeZona(z: Pick<Zone, 'name' | 'nameIdn'>): string {
  const name = z.name === '' ? '.' : z.name
  if (z.nameIdn == null) return name === '.' ? '<root>' : name
  return `${z.nameIdn} (${name})`
}

export interface ListaZonas {
  zones: Zone[]
  pageNumber: number
  totalPages: number
  totalZones: number
}

export const TIPOS_ZONA = ['Primary','Secondary','Stub','Forwarder','SecondaryForwarder','Catalog','SecondaryCatalog'] as const

/** Tamaños de página del desplegable de upstream (index.html, `optZonesPerPage`). */
export const ZONAS_POR_PAGINA = [10, 25, 50, 100, 250, 500] as const

export async function listZones(
  token: string | null,
  opciones: {
    filterName?: string
    filterType?: string
    pageNumber?: number
    zonesPerPage?: number
    node?: string
  } = {},
): Promise<ApiOutcome<ListaZonas>> {
  const {
    filterName = '',
    filterType = '',
    pageNumber = 1,
    zonesPerPage = 10,
    node = '',
  } = opciones
  const outcome = await apiRequest<{ response: ListaZonas }>('zones/list', {
    token,
    body: {
      filterName,
      filterType,
      pageNumber: String(pageNumber),
      zonesPerPage: String(zonesPerPage),
      node,
    },
  })
  /*
  Devuelve el resultado entero y no `ListaZonas | null`.

  Con `null` la pantalla no sabía POR QUÉ había fallado y decía siempre «Unable
  to reach the DNS server.», que es una afirmación concreta —la red está caída—
  y era falsa en los dos casos que de verdad pasan: el servidor contestando un
  error, y el servidor rechazando la sesión. En el segundo, además, mandaba a
  mirar la red a quien lo que tenía que hacer era volver a entrar.
  */
  if (outcome.kind !== 'ok') return outcome
  const r = outcome.data.response
  return {
    kind: 'ok',
    data: {
      zones: r.zones ?? [],
      pageNumber: r.pageNumber ?? 1,
      totalPages: r.totalPages ?? 1,
      totalZones: r.totalZones ?? (r.zones?.length ?? 0),
    },
  }
}

/** «never» cuando la fecha es el mínimo de .NET, que es lo que upstream muestra. */
export function nuncaUsado(iso: string): boolean {
  return !iso || iso.startsWith('0001-01-01')
}

/**
 * `zones/create` (zone.js:2911). Es POST pero **los parámetros van en la
 * query**, no en el cuerpo: el cuerpo se reserva para el fichero de zona
 * opcional, que viaja como multipart en el campo `fileImportZone`. Sin fichero,
 * upstream manda un POST sin cuerpo ninguno.
 */
export function createZone(
  token: string | null,
  parametros: Record<string, string>,
  archivo?: File | null,
  node = '',
): Promise<ApiOutcome<{ response: { domain: string } }>> {
  const query = new URLSearchParams({ ...parametros, node })
  return apiRequest<{ response: { domain: string } }>(`zones/create?${query.toString()}`, {
    token,
    method: 'POST',
    ...(archivo ? { file: { campo: 'fileImportZone', archivo } } : {}),
  })
}

export function deleteZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/delete', { token, body: { zone, node } })
}

export interface BorradoMultiple {
  response: { deleted: string[]; failed: Record<string, string> }
}

/**
 * El borrado en bloque usa el MISMO endpoint con el parámetro en plural
 * (`zones=`, separadas por coma) y devuelve dos listas: lo borrado y lo
 * fallido. No es un endpoint distinto, aunque lo parezca (zone.js:1140).
 */
export function deleteZones(
  token: string | null,
  zones: string[],
  node = '',
): Promise<ApiOutcome<BorradoMultiple>> {
  return apiRequest<BorradoMultiple>('zones/delete', {
    token,
    body: { zones: zones.join(','), node },
  })
}
export function enableZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/enable', { token, body: { zone, node } })
}
export function disableZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/disable', { token, body: { zone, node } })
}
export function resyncZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/resync', { token, body: { zone, node } })
}
export function cloneZone(
  token: string | null,
  zone: string,
  sourceZone: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/clone', { token, body: { zone, sourceZone, node } })
}
export function convertZone(
  token: string | null,
  zone: string,
  type: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/convert', { token, body: { zone, type, node } })
}
export async function listCatalogs(token: string | null, node = ''): Promise<string[] | null> {
  const outcome = await apiRequest<{ response: { catalogZoneNames: string[] } }>(
    'zones/catalogs/list',
    { token, body: { node } },
  )
  if (outcome.kind !== 'ok') return null
  return outcome.data.response.catalogZoneNames ?? []
}

/* ── Opciones de zona ──────────────────────────────────────────────────── */

export interface PoliticaActualizacion {
  tsigKeyName: string
  domain: string
  allowedTypes: string[]
}

export interface OpcionesZona {
  name: string
  type: string
  dnssecStatus: string
  disabled: boolean
  catalog: string | null
  notifyFailed?: boolean
  notifyFailedFor?: string[]
  /** Sólo en zonas que pertenecen a un catálogo. */
  overrideCatalogQueryAccess?: boolean
  overrideCatalogZoneTransfer?: boolean
  overrideCatalogNotify?: boolean
  primaryNameServerAddresses?: string[]
  primaryZoneTransferProtocol?: string
  primaryZoneTransferTsigKeyName?: string
  validateZone?: boolean
  queryAccess: string
  queryAccessNetworkACL: string[]
  zoneTransfer: string
  zoneTransferNetworkACL: string[]
  zoneTransferTsigKeyNames: string[]
  notify: string
  notifyNameServers: string[]
  notifySecondaryCatalogsNameServers?: string[]
  update: string
  updateNetworkACL: string[]
  updateSecurityPolicies: PoliticaActualizacion[]
  /** Sólo si se pide con `includeAvailableCatalogZoneNames`. */
  availableCatalogZoneNames?: string[]
  /** Sólo si se pide con `includeAvailableTsigKeyNames`. */
  availableTsigKeyNames?: string[]
  /*
  Los dos que gobiernan el bloqueo de casi todo el formulario y que sólo
  aparecen en zonas que pertenecen a un catálogo. `isSecondaryCatalogMember`
  significa que la zona la administra un catálogo secundario, y entonces la
  mitad de los controles se ven pero no se pueden tocar.
  */
  isSecondaryCatalogMember?: boolean
  overrideCatalogPrimaryNameServers?: boolean
}

export async function getZoneOptions(
  token: string | null,
  zone: string,
  node = '',
): Promise<OpcionesZona | null> {
  const outcome = await apiRequest<{ response: OpcionesZona }>('zones/options/get', {
    token,
    body: {
      zone,
      includeAvailableCatalogZoneNames: 'true',
      includeAvailableTsigKeyNames: 'true',
      node,
    },
  })
  return outcome.kind === 'ok' ? outcome.data.response : null
}

/** El cuerpo lo arma la pantalla, que es quien valida (ver screens/zones/opciones.ts). */
export function setZoneOptions(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/options/set', { token, body: { ...body, node } })
}

/* ── Permisos de zona ──────────────────────────────────────────────────── */

/*
El nombre del sujeto NO se llama igual en las dos tablas: un permiso de usuario
trae `username` y uno de grupo trae `name`. Verificado contra v15.4. Tratarlas
como la misma forma deja media tabla en blanco.
*/
export interface PermisoDeUsuario {
  username: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export interface PermisoDeGrupo {
  name: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export interface PermisosZona {
  section: string
  subItem: string
  userPermissions: PermisoDeUsuario[]
  groupPermissions: PermisoDeGrupo[]
  /** Sólo si se pide con `includeUsersAndGroups`. */
  users?: string[]
  groups?: string[]
}

export async function getZonePermissions(
  token: string | null,
  zone: string,
  node = '',
): Promise<PermisosZona | null> {
  const outcome = await apiRequest<{ response: PermisosZona }>('zones/permissions/get', {
    token,
    body: { zone, includeUsersAndGroups: 'true', node },
  })
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return {
    ...r,
    userPermissions: r.userPermissions ?? [],
    groupPermissions: r.groupPermissions ?? [],
  }
}

/**
 * `serializeTableData` con 4 columnas (common.js:282): nombre y los tres
 * booleanos de cada fila, todo unido por `|` en una sola cadena.
 */
export function serializarPermisos(
  filas: { nombre: string; canView: boolean; canModify: boolean; canDelete: boolean }[],
): string {
  const salida: string[] = []
  for (const f of filas) {
    salida.push(f.nombre, String(f.canView), String(f.canModify), String(f.canDelete))
  }
  return salida.join('|')
}

export function setZonePermissions(
  token: string | null,
  zone: string,
  userPermissions: string,
  groupPermissions: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/permissions/set', {
    token,
    body: { zone, userPermissions, groupPermissions, node },
  })
}

/* ── Importar y exportar ───────────────────────────────────────────────── */

export interface OpcionesImportacion {
  overwrite: boolean
  overwriteZone: boolean
  overwriteSoaSerial: boolean
}

/**
 * `zones/import` (zone.js:1251). Tiene **dos formas de mandar el fichero**, y
 * la diferencia no es cosmética: subiéndolo va como multipart en el campo
 * `fileImportZone`; pegándolo en el textarea va como **texto plano crudo** con
 * `Content-Type: text/plain`. El servidor distingue por ese tipo.
 *
 * Los tres interruptores viajan siempre en la query, igual que la zona.
 */
export function importZone(
  token: string | null,
  zone: string,
  fuente: { archivo: File } | { texto: string },
  opciones: OpcionesImportacion,
  node = '',
): Promise<ApiOutcome> {
  const query = new URLSearchParams({
    zone,
    overwrite: String(opciones.overwrite),
    overwriteZone: String(opciones.overwriteZone),
    overwriteSoaSerial: String(opciones.overwriteSoaSerial),
    node,
  })
  const ruta = `zones/import?${query.toString()}`

  if ('archivo' in fuente) {
    return apiRequest(ruta, { token, method: 'POST', file: { campo: 'fileImportZone', archivo: fuente.archivo } })
  }
  return apiRequest(ruta, { token, method: 'POST', texto: fuente.texto })
}

/**
 * `zones/export` (zone.js:1315). Una de las seis descargas del proyecto: no se
 * hace `fetch`, se pide un token de un solo uso y se abre una ventana. Sin ese
 * token la descarga viajaría con el de sesión en la URL.
 */
export function exportZone(
  token: string | null,
  zone: string,
  node = '',
): Promise<{ ok: boolean }> {
  // Sin `ts`: upstream no lo añade en esta descarga (zone.js:1322).
  return openDownload(token, 'zones/export', { zone, node })
}
