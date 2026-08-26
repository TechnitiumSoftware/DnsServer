import { apiRequest, type ApiOutcome } from './client'

/*
La familia `admin` sin el cluster: sesiones, usuarios, grupos, permisos y SSO.
Dieciocho endpoints, todos en `auth.js`. El cluster —doce más— vive en
`admin-cluster.ts` porque es otra pantalla y otro fichero de upstream.

Seis cosas del servidor que NO se deducen leyendo el JavaScript de upstream y
que gobiernan las pantallas:

  1. **Los permisos son asimétricos.** Todo esto cuelga de la sección
     `Administration`, pero no del mismo flag: listar y consultar piden `View`,
     crear y modificar piden `Modify`, borrar pide `Delete` … y
     `permissions/set` y `sso/set` piden **`Delete`**, no `Modify`
     (WebServiceAuthApi.cs:1533 y 1692). Quien pinte la interfaz no puede
     deducir el permiso por el nombre del verbo.

  2. **`admin/sso/set` NO devuelve `localGroups`.** `WriteSsoConfig` sólo los
     escribe con `includeGroups`, y el `set` lo llama con `false`
     (WebServiceAuthApi.cs:1790). Upstream sobrevive porque guarda la lista en
     una variable global al hacer el `get`; aquí hay que conservarla igual.

  3. **El secreto de cliente viaja enmascarado.** `WriteSsoConfig` devuelve
     `"************"` en cuanto hay uno guardado, y `SetSsoConfig` ignora ese
     valor exacto (líneas 339-342 y 1738). Es lo que permite guardar el
     formulario sin volver a teclear el secreto: se manda tal cual llegó.

  4. **Cada endpoint devuelve una forma distinta del mismo usuario.**
     `users/get?includeGroups=true` trae `groups` (todos los grupos del
     servidor, para el desplegable); `users/set` NO lo trae aunque sí traiga
     `memberOfGroups` y `sessions`; `users/list` y `users/create` no traen
     ninguno de los tres. Verificado contra una instancia v15.4.

  5. **La lista de grupos de `permissions/get` NO es la de `groups/list`.**
     La primera incluye `Everyone` y la segunda no. Comprobado en vivo.

  6. **Borrar una sesión que no existe SÍ da error** («No such active session
     was found for partial token: …»), al revés que la mayoría de los borrados
     de esta API. Comprobado en vivo.

`node` es el nodo del cluster al que se dirige la petición
(DnsWebService.cs:2367); vacío significa «este servidor». Sólo lo mandan
`sessions/list`, `sessions/delete` y `permissions/set`, y no siempre el mismo
valor: ver los comentarios de cada función.
*/

export interface AdminSession {
  username: string
  isCurrentSession: boolean
  partialToken: string
  /** `Standard`, `ApiToken`, `ClusterApiToken` … lo demás se pinta «Unknown». */
  type: string
  tokenName: string | null
  lastSeen: string
  lastSeenRemoteAddress: string
  lastSeenUserAgent: string
}

export interface AdminUser {
  displayName: string
  username: string
  isSsoUser: boolean
  totpEnabled: boolean
  disabled: boolean
  previousSessionLoggedOn: string
  previousSessionRemoteAddress: string
  recentSessionLoggedOn: string
  recentSessionRemoteAddress: string
}

export interface AdminUserDetails extends AdminUser {
  sessionTimeoutSeconds: number
  ssoManagedGroups: boolean
  memberOfGroups: string[]
  sessions: AdminSession[]
  /** Sólo con `includeGroups=true`: TODOS los grupos del servidor. */
  groups?: string[]
}

export interface AdminGroup {
  name: string
  description: string
}

export interface AdminGroupDetails extends AdminGroup {
  members: string[]
  /** Sólo con `includeUsers=true`: TODOS los usuarios del servidor. */
  users?: string[]
}

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

export interface SectionPermission {
  section: string
  userPermissions: UserPermission[]
  groupPermissions: GroupPermission[]
}

export interface SectionPermissionDetails extends SectionPermission {
  /** Sólo con `includeUsersAndGroups=true`. */
  users?: string[]
  /** Sólo con `includeUsersAndGroups=true`. Incluye `Everyone`. */
  groups?: string[]
}

export interface SsoGroupMapEntry {
  remoteGroup: string
  localGroup: string
}

export interface SsoConfig {
  ssoEnabled: boolean
  ssoAuthority: string | null
  ssoClientId: string | null
  /** `"************"` cuando hay uno guardado; `null` cuando no. */
  ssoClientSecret: string | null
  ssoMetadataAddress: string | null
  ssoScopes: string[]
  ssoAllowSignup: boolean
  ssoAllowSignupOnlyForMappedUsers: boolean
  ssoGroupMap: SsoGroupMapEntry[]
  /** Sólo en `sso/get?includeGroups=true`. Excluye `Everyone`. */
  localGroups?: string[]
}

export interface CreatedApiToken {
  username: string
  tokenName: string
  token: string
}

type Env<T> = { response: T; server: string }

/* --------------------------------------------------------------- sesiones */

/** `refreshAdminSessions` (auth.js:856). El `server` de la envoltura hace falta:
 *  el botón «Create Token» sólo se ve si este servidor es el nodo primario. */
export function listSessions(
  token: string | null,
  node = '',
): Promise<ApiOutcome<Env<{ sessions: AdminSession[] }>>> {
  return apiRequest('admin/sessions/list', { token, body: { node } })
}

/** `createApiToken` (auth.js:988). Permiso `Administration.canModify`. */
export function createApiToken(
  token: string | null,
  user: string,
  tokenName: string,
): Promise<ApiOutcome<Env<CreatedApiToken>>> {
  return apiRequest('admin/sessions/createToken', { token, body: { user, tokenName } })
}

/*
`deleteAdminSession` (auth.js:1040) y `deleteUserSession` (auth.js:1371) borran
lo mismo con URLs DISTINTAS, y no es un descuido: desde la pestaña Sessions
siempre viaja un `node` (el primario si la sesión es un token de API, el nodo
elegido en cualquier otro caso) y desde el modal de detalles del usuario el
`node` viaja SÓLO si la sesión es un token de API. Por eso `node` es opcional
aquí: `undefined` significa «no mandes el parámetro».
*/
export function deleteAdminSession(
  token: string | null,
  partialToken: string,
  node?: string,
): Promise<ApiOutcome> {
  const body: Record<string, string> = { partialToken }
  if (node !== undefined) body.node = node
  return apiRequest('admin/sessions/delete', { token, body })
}

/* --------------------------------------------------------------- usuarios */

export function listUsers(
  token: string | null,
): Promise<ApiOutcome<Env<{ users: AdminUser[] }>>> {
  return apiRequest('admin/users/list', { token })
}

/*
`addUser` (auth.js:1178). Upstream lo manda por POST porque lleva contraseña.

`displayName` es opcional y de hecho el formulario no lo valida: si va vacío, el
servidor devuelve el nombre de usuario como nombre visible. Comprobado en vivo.
*/
export function createUser(
  token: string | null,
  displayName: string,
  user: string,
  pass: string,
): Promise<ApiOutcome<Env<AdminUser>>> {
  return apiRequest('admin/users/create', {
    token,
    method: 'POST',
    body: { displayName, user, pass },
  })
}

export function getUser(
  token: string | null,
  user: string,
): Promise<ApiOutcome<Env<AdminUserDetails>>> {
  return apiRequest('admin/users/get', { token, body: { user, includeGroups: 'true' } })
}

/*
`admin/users/set` es un endpoint parcial: el servidor sólo toca lo que llega
(`TryGetQueryOrForm`, WebServiceAuthApi.cs:1065-1225). Upstream se apoya en eso
para cinco acciones distintas con el mismo endpoint —guardar el modal, activar,
desactivar, quitar el 2FA y resetear la contraseña— mandando cada vez sólo los
campos de esa acción. De ahí que aquí el cuerpo sea abierto.
*/
export function setUser(
  token: string | null,
  body: Record<string, string>,
): Promise<ApiOutcome<Env<AdminUserDetails>>> {
  return apiRequest('admin/users/set', { token, body })
}

/** `resetUserPassword` (auth.js:1572). Por POST, que lleva la contraseña nueva. */
export function resetUserPassword(
  token: string | null,
  user: string,
  newPass: string,
): Promise<ApiOutcome<Env<AdminUserDetails>>> {
  return apiRequest('admin/users/set', { token, method: 'POST', body: { user, newPass } })
}

export function deleteUser(token: string | null, user: string): Promise<ApiOutcome> {
  return apiRequest('admin/users/delete', { token, body: { user } })
}

/* ----------------------------------------------------------------- grupos */

export function listGroups(
  token: string | null,
): Promise<ApiOutcome<Env<{ groups: AdminGroup[] }>>> {
  return apiRequest('admin/groups/list', { token })
}

export function createGroup(
  token: string | null,
  group: string,
  description: string,
): Promise<ApiOutcome<Env<AdminGroup>>> {
  return apiRequest('admin/groups/create', { token, body: { group, description } })
}

export function getGroup(
  token: string | null,
  group: string,
): Promise<ApiOutcome<Env<AdminGroupDetails>>> {
  return apiRequest('admin/groups/get', { token, body: { group, includeUsers: 'true' } })
}

/*
`saveGroupDetails` (auth.js:1860). `newGroup` sólo viaja si el nombre cambió:
mandarlo siempre haría que el servidor renombrase el grupo a sí mismo.

Y la respuesta NO es la misma que la de `groups/create`: ésta trae `members` y
aquélla no. Comprobado en vivo contra una v15.4.
*/
export function setGroup(
  token: string | null,
  group: string,
  description: string,
  members: string,
  newGroup?: string,
): Promise<ApiOutcome<Env<AdminGroupDetails>>> {
  const body: Record<string, string> = { group, description, members }
  if (newGroup !== undefined) body.newGroup = newGroup
  return apiRequest('admin/groups/set', { token, body })
}

export function deleteGroup(token: string | null, group: string): Promise<ApiOutcome> {
  return apiRequest('admin/groups/delete', { token, body: { group } })
}

/* --------------------------------------------------------------- permisos */

export function listPermissions(
  token: string | null,
): Promise<ApiOutcome<Env<{ permissions: SectionPermission[] }>>> {
  return apiRequest('admin/permissions/list', { token })
}

export function getPermission(
  token: string | null,
  section: string,
): Promise<ApiOutcome<Env<SectionPermissionDetails>>> {
  return apiRequest('admin/permissions/get', {
    token,
    body: { section, includeUsersAndGroups: 'true' },
  })
}

/*
`saveSectionPermissions` (auth.js:2114). Las dos tablas viajan serializadas con
`|` como separador ÚNICO —tanto entre columnas como entre filas—, que es lo que
hace `serializeTableData` (common.js:282). Y el `node` NO es el nodo elegido en
la pantalla: es siempre el nodo PRIMARIO del cluster, o cadena vacía si no hay
cluster.
*/
export function setPermissions(
  token: string | null,
  section: string,
  userPermissions: string,
  groupPermissions: string,
  node: string,
): Promise<ApiOutcome<Env<SectionPermission>>> {
  return apiRequest('admin/permissions/set', {
    token,
    body: { section, userPermissions, groupPermissions, node },
  })
}

/* -------------------------------------------------------------------- SSO */

export function getSsoConfig(token: string | null): Promise<ApiOutcome<Env<SsoConfig>>> {
  return apiRequest('admin/sso/get', { token, body: { includeGroups: 'true' } })
}

/** `saveAdminSsoConfig` (auth.js:2233). Por POST porque lleva el secreto. */
export function setSsoConfig(
  token: string | null,
  body: Record<string, string>,
): Promise<ApiOutcome<Env<SsoConfig>>> {
  return apiRequest('admin/sso/set', { token, method: 'POST', body })
}
