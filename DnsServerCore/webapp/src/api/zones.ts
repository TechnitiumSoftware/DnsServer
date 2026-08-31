import { apiRequest, type ApiOutcome } from './client'
import { openDownload } from './user'

/*
The `zones` family, the zone-management part: 15 endpoints. The 4 of
`zones/records/*` live in registros.ts and the 15 of DNSSEC in dnssec.ts. Between
the three they add up to the 34 of phase 4.

TWO DIFFERENT PAGINATIONS, and this one is easy to get wrong:

  · `zones/list` PAGINATES ON THE SERVER: it is sent `pageNumber` and
    `zonesPerPage`, and returns `pageNumber`, `totalPages` and `totalZones`.
    Careful: those three fields **only appear if you send `pageNumber`**;
    without it the response brings only `zones`.

  · `zones/records/get` does NOT paginate (see registros.ts).

`node` is the cluster node the request is aimed at (`optZonesClusterNode`). With
a single instance it goes empty, and that is how upstream sends it: the string
`&node=` travels all the same in the 40 calls of zone.js.
*/

/*
Be suspicious of every optional field. Checked against a freshly installed v15.4:

  · `zones/list` does NOT return the five that govern the state (`isExpired`,
    `validationFailed`, `syncFailed`, `expiry`) nor `nameIdn` except on
    secondary, expired or internationalised-name zones.

  · And the least expected one: **a Catalog or Forwarder zone omits
    `dnssecStatus` and `hasDnssecPrivateKeys`**, and the Catalog also omits
    `catalog`. They are types that cannot be signed, so the server does not even
    write them. Declaring them required lies about half the list.
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
  /** Internationalised name; only on zones with non-ASCII characters. */
  nameIdn?: string
  /** Only on the server's internal zones: they cannot be deleted or edited. */
  internal?: boolean
}

/**
 * The state drawn in the row, with the EXACT priority of `refreshZones`
 * (zone.js:733-745). It is neither alphabetical nor by severity: it is
 * upstream's chain of `else if` and the order matters — a zone that is expired
 * and has a failed notify says "Expired", not "Notify Failed".
 */
export type ZoneState = 'Disabled' | 'Expired' | 'Validation Failed' | 'Sync Failed' | 'Notify Failed' | 'Enabled'

export function zoneState(z: Zone): ZoneState {
  if (z.disabled) return 'Disabled'
  if (z.isExpired) return 'Expired'
  if (z.validationFailed) return 'Validation Failed'
  if (z.syncFailed) return 'Sync Failed'
  if (z.notifyFailed) return 'Notify Failed'
  return 'Enabled'
}

/** The type's text: only the two "Secondary…" split into two words. */
export function typeLabel(type: string): string {
  if (type === 'SecondaryForwarder') return 'Secondary Forwarder'
  if (type === 'SecondaryCatalog') return 'Secondary Catalog'
  return type
}

/** The name that is drawn: the root is `<root>` and an IDN carries both. */
export function zoneNameOf(z: Pick<Zone, 'name' | 'nameIdn'>): string {
  const name = z.name === '' ? '.' : z.name
  if (z.nameIdn == null) return name === '.' ? '<root>' : name
  return `${z.nameIdn} (${name})`
}

export interface ZoneList {
  zones: Zone[]
  pageNumber: number
  totalPages: number
  totalZones: number
}

export const ZONE_TYPES = ['Primary','Secondary','Stub','Forwarder','SecondaryForwarder','Catalog','SecondaryCatalog'] as const

/** Page sizes of upstream's dropdown (index.html, `optZonesPerPage`). */
export const ZONES_PER_PAGE = [10, 25, 50, 100, 250, 500] as const

export async function listZones(
  token: string | null,
  options: {
    filterName?: string
    filterType?: string
    pageNumber?: number
    zonesPerPage?: number
    node?: string
  } = {},
): Promise<ApiOutcome<ZoneList>> {
  const {
    filterName = '',
    filterType = '',
    pageNumber = 1,
    zonesPerPage = 10,
    node = '',
  } = options
  const outcome = await apiRequest<{ response: ZoneList }>('zones/list', {
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
  Returns the whole outcome and not `ListaZonas | null`.

  With `null` the screen did not know WHY it had failed and always said "Unable
  to reach the DNS server.", which is a concrete claim —the network is down— and
  was false in the two cases that actually happen: the server answering an error,
  and the server rejecting the session. In the second one it also sent someone to
  go look at the network when what they had to do was log back in.
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

/** "never" when the date is .NET's minimum, which is what upstream shows. */
export function neverUsed(iso: string): boolean {
  return !iso || iso.startsWith('0001-01-01')
}

/**
 * `zones/create` (zone.js:2911). It is a POST but **the parameters go in the
 * query**, not in the body: the body is reserved for the optional zone file,
 * which travels as multipart in the `fileImportZone` field. Without a file,
 * upstream sends a POST with no body at all.
 */
export function createZone(
  token: string | null,
  params: Record<string, string>,
  archivo?: File | null,
  node = '',
): Promise<ApiOutcome<{ response: { domain: string } }>> {
  const query = new URLSearchParams({ ...params, node })
  return apiRequest<{ response: { domain: string } }>(`zones/create?${query.toString()}`, {
    token,
    method: 'POST',
    ...(archivo ? { file: { field: 'fileImportZone', archivo } } : {}),
  })
}

export function deleteZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/delete', { token, body: { zone, node } })
}

export interface BorradoMultiple {
  response: { deleted: string[]; failed: Record<string, string> }
}

/**
 * The bulk delete uses the SAME endpoint with the parameter in plural (`zones=`,
 * comma-separated) and returns two lists: what was deleted and what failed. It
 * is not a different endpoint, however much it looks like one (zone.js:1140).
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

export interface ZoneOptions {
  name: string
  type: string
  dnssecStatus: string
  disabled: boolean
  catalog: string | null
  notifyFailed?: boolean
  notifyFailedFor?: string[]
  /** Only on zones that belong to a catalog. */
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
  /** Only if asked for with `includeAvailableCatalogZoneNames`. */
  availableCatalogZoneNames?: string[]
  /** Only if asked for with `includeAvailableTsigKeyNames`. */
  availableTsigKeyNames?: string[]
  /*
  The two that govern the locking of nearly the whole form and that only appear
  on zones belonging to a catalog. `isSecondaryCatalogMember` means the zone is
  administered by a secondary catalog, and then half the controls are visible but
  cannot be touched.
  */
  isSecondaryCatalogMember?: boolean
  overrideCatalogPrimaryNameServers?: boolean
}

export async function getZoneOptions(
  token: string | null,
  zone: string,
  node = '',
): Promise<ZoneOptions | null> {
  const outcome = await apiRequest<{ response: ZoneOptions }>('zones/options/get', {
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

/** The body is built by the screen, which is the one that validates (see screens/zones/opciones.ts). */
export function setZoneOptions(
  token: string | null,
  body: Record<string, string>,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/options/set', { token, body: { ...body, node } })
}

/* ── Permisos de zona ──────────────────────────────────────────────────── */

/*
The subject's name is NOT called the same in the two tables: a user permission
brings `username` and a group one brings `name`. Verified against v15.4. Treating
them as the same shape leaves half the table blank.
*/
export interface UserPermission {
  username: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export interface GroupPermission {
  name: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export interface ZonePermissions {
  section: string
  subItem: string
  userPermissions: UserPermission[]
  groupPermissions: GroupPermission[]
  /** Only if asked for with `includeUsersAndGroups`. */
  users?: string[]
  groups?: string[]
}

export async function getZonePermissions(
  token: string | null,
  zone: string,
  node = '',
): Promise<ZonePermissions | null> {
  const outcome = await apiRequest<{ response: ZonePermissions }>('zones/permissions/get', {
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
 * `serializeTableData` with 4 columns (common.js:282): the name and the three
 * booleans of each row, all joined by `|` into a single string.
 */
export function serializePermissions(
  rows: { name: string; canView: boolean; canModify: boolean; canDelete: boolean }[],
): string {
  const salida: string[] = []
  for (const f of rows) {
    salida.push(f.name, String(f.canView), String(f.canModify), String(f.canDelete))
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

export interface ImportOptions {
  overwrite: boolean
  overwriteZone: boolean
  overwriteSoaSerial: boolean
}

/**
 * `zones/import` (zone.js:1251). It has **two ways of sending the file**, and
 * the difference is not cosmetic: uploading it goes as multipart in the
 * `fileImportZone` field; pasting it into the textarea goes as **raw plain
 * text** with `Content-Type: text/plain`. The server tells them apart by that
 * type.
 *
 * The three switches always travel in the query, same as the zone.
 */
export function importZone(
  token: string | null,
  zone: string,
  fuente: { archivo: File } | { text: string },
  options: ImportOptions,
  node = '',
): Promise<ApiOutcome> {
  const query = new URLSearchParams({
    zone,
    overwrite: String(options.overwrite),
    overwriteZone: String(options.overwriteZone),
    overwriteSoaSerial: String(options.overwriteSoaSerial),
    node,
  })
  const route = `zones/import?${query.toString()}`

  if ('archivo' in fuente) {
    return apiRequest(route, { token, method: 'POST', file: { field: 'fileImportZone', archivo: fuente.archivo } })
  }
  return apiRequest(route, { token, method: 'POST', text: fuente.text })
}

/**
 * `zones/export` (zone.js:1315). One of the project's six downloads: there is no
 * `fetch`, a single-use token is asked for and a window is opened. Without that
 * token the download would travel with the session one in the URL.
 */
export function exportZone(
  token: string | null,
  zone: string,
  node = '',
): Promise<{ ok: boolean }> {
  // No `ts`: upstream does not add it on this download (zone.js:1322).
  return openDownload(token, 'zones/export', { zone, node })
}
