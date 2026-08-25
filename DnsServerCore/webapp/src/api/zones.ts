import { apiRequest, type ApiOutcome } from './client'

/*
Familia `zones`. 34 endpoints en total; aquí van los de gestión de zonas y sus
registros. Los 12 de `zones/dnssec/properties/*` viven en dnssec.ts.

DOS PAGINACIONES DISTINTAS, y esto es fácil de equivocar:

  · `zones/list` PAGINA EN EL SERVIDOR: se le mandan `pageNumber` y
    `zonesPerPage`, y devuelve `pageNumber`, `totalPages` y `totalZones`.
    Ojo: esos tres campos **sólo aparecen si mandas `pageNumber`**; sin él la
    respuesta trae únicamente `zones`.

  · `zones/records/get` NO pagina: upstream lo pide con `listZone=true` y sin
    parámetros de página (zone.js), recibe TODOS los registros y pagina en el
    cliente. Verificado contra v15.4: mandarle `recordsPerPage` no cambia nada.
*/

export interface Zone {
  name: string
  type: string
  lastModified: string
  disabled: boolean
  soaSerial: number | null
  catalog: string | null
  dnssecStatus: string
  hasDnssecPrivateKeys: boolean
  notifyFailed: boolean
  notifyFailedFor: string[]
  expiry?: string
}

export interface ListaZonas {
  zones: Zone[]
  pageNumber: number
  totalPages: number
  totalZones: number
}

export const TIPOS_ZONA = ['Primary','Secondary','Stub','Forwarder','SecondaryForwarder','Catalog','SecondaryCatalog'] as const

export async function listZones(
  token: string | null,
  opciones: { filterName?: string; filterType?: string; pageNumber?: number; zonesPerPage?: number } = {},
): Promise<ListaZonas | null> {
  const { filterName = '', filterType = '', pageNumber = 1, zonesPerPage = 10 } = opciones
  const outcome = await apiRequest<{ response: ListaZonas }>('zones/list', {
    token,
    body: {
      filterName,
      filterType,
      pageNumber: String(pageNumber),
      zonesPerPage: String(zonesPerPage),
    },
  })
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return {
    zones: r.zones ?? [],
    pageNumber: r.pageNumber ?? 1,
    totalPages: r.totalPages ?? 1,
    totalZones: r.totalZones ?? (r.zones?.length ?? 0),
  }
}

export interface Registro {
  name: string
  type: string
  ttl: number
  ttlString: string
  disabled: boolean
  rData: Record<string, unknown>
  dnssecStatus: string
  lastUsedOn: string
  lastModified: string
  expiryTtl: number
  expiryTtlString: string
  comments?: string
}

export interface RegistrosDeZona {
  zone: Zone & { internal?: boolean }
  records: Registro[]
}

export async function getRecords(token: string | null, zone: string): Promise<RegistrosDeZona | null> {
  const outcome = await apiRequest<{ response: RegistrosDeZona }>('zones/records/get', {
    token,
    body: { domain: zone, zone, listZone: 'true' },
  })
  return outcome.kind === 'ok' ? outcome.data.response : null
}

/** «never» cuando la fecha es el mínimo de .NET, que es lo que upstream muestra. */
export function nuncaUsado(iso: string): boolean {
  return !iso || iso.startsWith('0001-01-01')
}

export function createZone(token: string | null, zone: string, type: string): Promise<ApiOutcome> {
  return apiRequest('zones/create', { token, body: { zone, type } })
}
export function deleteZone(token: string | null, zone: string): Promise<ApiOutcome> {
  return apiRequest('zones/delete', { token, body: { zone } })
}
export function enableZone(token: string | null, zone: string): Promise<ApiOutcome> {
  return apiRequest('zones/enable', { token, body: { zone } })
}
export function disableZone(token: string | null, zone: string): Promise<ApiOutcome> {
  return apiRequest('zones/disable', { token, body: { zone } })
}
export function resyncZone(token: string | null, zone: string): Promise<ApiOutcome> {
  return apiRequest('zones/resync', { token, body: { zone } })
}
export function cloneZone(token: string | null, zone: string, sourceZone: string): Promise<ApiOutcome> {
  return apiRequest('zones/clone', { token, body: { zone, sourceZone } })
}
export function convertZone(token: string | null, zone: string, type: string): Promise<ApiOutcome> {
  return apiRequest('zones/convert', { token, body: { zone, type } })
}
export function listCatalogs(token: string | null): Promise<ApiOutcome<{ response: { catalogZoneNames: string[] } }>> {
  return apiRequest('zones/catalogs/list', { token })
}
export function getZoneOptions(token: string | null, zone: string) {
  return apiRequest<{ response: Record<string, unknown> }>('zones/options/get', {
    token,
    body: { zone, includeAvailableCatalogZoneNames: 'true' },
  })
}
export function getZonePermissions(token: string | null, zone: string) {
  return apiRequest<{ response: Record<string, unknown> }>('zones/permissions/get', {
    token,
    body: { zone, includeUsersAndGroups: 'true' },
  })
}

/** Importar una zona es una subida multipart (zone.js:1273). */
export function importZone(
  token: string | null,
  zone: string,
  archivo: File,
  opciones: { overwrite?: boolean; overwriteSoaSerial?: boolean } = {},
): Promise<ApiOutcome> {
  return apiRequest('zones/import', {
    token,
    body: {
      zone,
      overwrite: String(opciones.overwrite ?? false),
      overwriteSoaSerial: String(opciones.overwriteSoaSerial ?? false),
    },
    file: { campo: 'fileZone', archivo },
  })
}
