import { apiRequest, type ApiOutcome } from './client'

/*
The `admin` family without the cluster: sessions, users, groups, permissions and
SSO. Eighteen endpoints, all of them in `auth.js`. The cluster —twelve more—
lives in `admin-cluster.ts` because it is another screen and another upstream
file.

Six things about the server that are NOT deducible from reading upstream's
JavaScript and that govern the screens:

  1. **The permissions are asymmetric.** All of this hangs off the
     `Administration` section, but not off the same flag: listing and reading ask
     for `View`, creating and modifying ask for `Modify`, deleting asks for
     `Delete` … and `permissions/set` and `sso/set` ask for **`Delete`**, not
     `Modify` (WebServiceAuthApi.cs:1533 and 1692). Whoever draws the interface
     cannot deduce the permission from the name of the verb.

  2. **`admin/sso/set` does NOT return `localGroups`.** `WriteSsoConfig` only
     writes them with `includeGroups`, and the `set` calls it with `false`
     (WebServiceAuthApi.cs:1790). Upstream survives because it keeps the list in
     a global variable when doing the `get`; here it has to be kept just the same.

  3. **The client secret travels masked.** `WriteSsoConfig` returns
     `"************"` as soon as one is stored, and `SetSsoConfig` ignores that
     exact value (lines 339-342 and 1738). That is what allows saving the form
     without typing the secret again: it is sent back exactly as it arrived.

  4. **Each endpoint returns a different shape of the same user.**
     `users/get?includeGroups=true` brings `groups` (every group on the server,
     for the dropdown); `users/set` does NOT bring it even though it does bring
     `memberOfGroups` and `sessions`; `users/list` and `users/create` bring none
     of the three. Verified against a v15.4 instance.

  5. **The group list of `permissions/get` is NOT the one of `groups/list`.**
     The first includes `Everyone` and the second does not. Checked live.

  6. **Deleting a session that does not exist DOES error** ("No such active
     session was found for partial token: …"), the opposite of most of the
     deletes in this API. Checked live.

`node` is the cluster node the request is aimed at (DnsWebService.cs:2367); empty
means "this server". Only `sessions/list`, `sessions/delete` and
`permissions/set` send it, and not always the same value: see the comments on
each function.
*/

export interface AdminSession {
  username: string
  isCurrentSession: boolean
  partialToken: string
  /** `Standard`, `ApiToken`, `ClusterApiToken` … anything else draws "Unknown". */
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
  /** Only with `includeGroups=true`: EVERY group on the server. */
  groups?: string[]
}

export interface AdminGroup {
  name: string
  description: string
}

export interface AdminGroupDetails extends AdminGroup {
  members: string[]
  /** Only with `includeUsers=true`: EVERY user on the server. */
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
  /** Only with `includeUsersAndGroups=true`. */
  users?: string[]
  /** Only with `includeUsersAndGroups=true`. Includes `Everyone`. */
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
  /** `"************"` when one is stored; `null` when not. */
  ssoClientSecret: string | null
  ssoMetadataAddress: string | null
  ssoScopes: string[]
  ssoAllowSignup: boolean
  ssoAllowSignupOnlyForMappedUsers: boolean
  ssoGroupMap: SsoGroupMapEntry[]
  /** Only in `sso/get?includeGroups=true`. Excludes `Everyone`. */
  localGroups?: string[]
}

export interface CreatedApiToken {
  username: string
  tokenName: string
  token: string
}

type Env<T> = { response: T; server: string }

/* --------------------------------------------------------------- sesiones */

/** `refreshAdminSessions` (auth.js:856). The `server` of the envelope is needed:
 *  the "Create Token" button only shows if this server is the primary node. */
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
`deleteAdminSession` (auth.js:1040) and `deleteUserSession` (auth.js:1371) delete
the same thing with DIFFERENT URLs, and it is not an oversight: from the Sessions
tab a `node` always travels (the primary if the session is an API token, the
chosen node in any other case), and from the user's details modal the `node`
travels ONLY if the session is an API token. That is why `node` is optional here:
`undefined` means "do not send the parameter".
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
`addUser` (auth.js:1178). Upstream sends it by POST because it carries a password.

`displayName` is optional and in fact the form does not validate it: if it goes
empty, the server returns the username as the display name. Checked live.
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
`admin/users/set` is a partial endpoint: the server only touches what arrives
(`TryGetQueryOrForm`, WebServiceAuthApi.cs:1065-1225). Upstream leans on that for
five different actions through the same endpoint —save the modal, enable,
disable, clear the 2FA and reset the password— sending only the fields of that
action each time. Hence the open body here.
*/
export function setUser(
  token: string | null,
  body: Record<string, string>,
): Promise<ApiOutcome<Env<AdminUserDetails>>> {
  return apiRequest('admin/users/set', { token, body })
}

/** `resetUserPassword` (auth.js:1572). By POST, since it carries the new password. */
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
`saveGroupDetails` (auth.js:1860). `newGroup` only travels if the name changed:
always sending it would make the server rename the group to itself.

And the response is NOT the same as `groups/create`'s: this one brings `members`
and that one does not. Checked live against a v15.4.
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
`saveSectionPermissions` (auth.js:2114). Both tables travel serialised with `|`
as the ONLY separator —between columns as well as between rows—, which is what
`serializeTableData` does (common.js:282). And the `node` is NOT the node chosen
on the screen: it is always the cluster's PRIMARY node, or an empty string if
there is no cluster.
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

/** `saveAdminSsoConfig` (auth.js:2233). By POST because it carries the secret. */
export function setSsoConfig(
  token: string | null,
  body: Record<string, string>,
): Promise<ApiOutcome<Env<SsoConfig>>> {
  return apiRequest('admin/sso/set', { token, method: 'POST', body })
}
