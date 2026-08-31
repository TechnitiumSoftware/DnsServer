import type {
  AdminGroup,
  AdminSession,
  AdminUser,
  AdminUserDetails,
  SectionPermission,
  SsoConfig,
} from '../../api/admin'
import type { ClusterState } from '../../api/admin-cluster'

/*
Real responses copied from a v15.4 instance (the `ref` one in `dev/`), not
invented. The odd shapes they bring are the subject of several tests:
`tokenName: null`, `0001-01-01T00:00:00` as "never", `0.0.0.0` as the address of
a session that never existed, and a `clusterState` WITHOUT `clusterNodes` because
the cluster is not initialised.
*/

export const SESION_ADMIN: AdminSession = {
  username: 'admin',
  isCurrentSession: true,
  partialToken: '5fc1a6bc90cc1d9a',
  type: 'Standard',
  tokenName: null,
  lastSeen: '2026-08-26T05:29:17.1433348Z',
  lastSeenRemoteAddress: '172.23.0.1',
  lastSeenUserAgent: 'curl/8.18.0',
}

export const SESION_TOKEN: AdminSession = {
  username: 'testuser',
  isCurrentSession: false,
  partialToken: '799a4919af7636e2',
  type: 'ApiToken',
  tokenName: 'tok1',
  lastSeen: '2026-08-26T05:29:41.6606519Z',
  lastSeenRemoteAddress: '172.23.0.1',
  lastSeenUserAgent: 'curl/8.18.0',
}

export const USUARIO_ADMIN: AdminUser = {
  displayName: 'Administrator',
  username: 'admin',
  isSsoUser: false,
  totpEnabled: false,
  disabled: false,
  previousSessionLoggedOn: '2026-08-26T05:29:16.3059242Z',
  previousSessionRemoteAddress: '172.23.0.1',
  recentSessionLoggedOn: '2026-08-26T05:29:17.122235Z',
  recentSessionRemoteAddress: '172.23.0.1',
}

/** A freshly created user: they have never logged in. */
export const USUARIO_NUEVO: AdminUser = {
  displayName: 'Test User',
  username: 'testuser',
  isSsoUser: false,
  totpEnabled: false,
  disabled: false,
  previousSessionLoggedOn: '0001-01-01T00:00:00',
  previousSessionRemoteAddress: '0.0.0.0',
  recentSessionLoggedOn: '0001-01-01T00:00:00',
  recentSessionRemoteAddress: '0.0.0.0',
}

export const USUARIO_SSO: AdminUser = {
  ...USUARIO_NUEVO,
  displayName: 'Adrián',
  username: 'adrian@example.com',
  isSsoUser: true,
  totpEnabled: false,
}

export const DETALLE_USUARIO: AdminUserDetails = {
  ...USUARIO_NUEVO,
  sessionTimeoutSeconds: 1800,
  ssoManagedGroups: false,
  memberOfGroups: [],
  sessions: [],
  groups: ['Administrators', 'DHCP Administrators', 'DNS Administrators'],
}

export const GRUPOS: AdminGroup[] = [
  { name: 'Administrators', description: 'Super administrators' },
  { name: 'DHCP Administrators', description: 'DHCP service administrators' },
  { name: 'DNS Administrators', description: 'DNS service administrators' },
]

export const PERMISOS: SectionPermission[] = [
  {
    section: 'Dashboard',
    userPermissions: [],
    groupPermissions: [
      { name: 'Administrators', canView: true, canModify: true, canDelete: true },
      { name: 'Everyone', canView: true, canModify: false, canDelete: false },
    ],
  },
  {
    section: 'Zones',
    userPermissions: [{ username: 'testuser', canView: true, canModify: false, canDelete: false }],
    groupPermissions: [
      { name: 'Administrators', canView: true, canModify: true, canDelete: true },
    ],
  },
]

export const SSO: SsoConfig = {
  ssoEnabled: false,
  ssoAuthority: null,
  ssoClientId: null,
  ssoClientSecret: null,
  ssoMetadataAddress: null,
  ssoScopes: ['openid', 'profile', 'email'],
  ssoAllowSignup: false,
  ssoAllowSignupOnlyForMappedUsers: true,
  ssoGroupMap: [],
  localGroups: ['Administrators', 'DHCP Administrators', 'DNS Administrators'],
}

/** A standalone server: `clusterDomain`, the intervals and `clusterNodes` do NOT
 *  come. It is the literal response of the reference instance. */
export const CLUSTER_SIN_INICIAR: ClusterState = {
  version: '15.4',
  dnsServerDomain: 'ref.technitium-ui.test',
  clusterInitialized: false,
}

/** A two-node cluster, built from the contract in `WebServiceClusterApi.cs`: it
 *  could NOT be observed live. */
export const CLUSTER_PRIMARIO: ClusterState = {
  version: '15.4',
  dnsServerDomain: 'ns1.micluster.test',
  clusterInitialized: true,
  clusterDomain: 'micluster.test',
  heartbeatRefreshIntervalSeconds: 30,
  heartbeatRetryIntervalSeconds: 10,
  configRefreshIntervalSeconds: 900,
  configRetryIntervalSeconds: 60,
  clusterNodes: [
    {
      id: 1,
      name: 'ns1.micluster.test',
      url: 'https://ns1.micluster.test:53443',
      ipAddresses: ['10.0.0.1'],
      type: 'Primary',
      state: 'Self',
      upSince: '2026-08-25T10:00:00Z',
    },
    {
      id: 2,
      name: 'ns2.micluster.test',
      url: 'https://ns2.micluster.test:53443',
      ipAddresses: ['10.0.0.2'],
      type: 'Secondary',
      state: 'Connected',
      upSince: '2026-08-25T10:05:00Z',
      lastSeen: '2026-08-26T05:00:00Z',
    },
  ],
}

/** The same cluster seen FROM the secondary. */
export const CLUSTER_SECUNDARIO: ClusterState = {
  ...CLUSTER_PRIMARIO,
  dnsServerDomain: 'ns2.micluster.test',
  clusterNodes: [
    {
      ...CLUSTER_PRIMARIO.clusterNodes![0],
      state: 'Connected',
      lastSeen: '2026-08-26T05:00:00Z',
    },
    {
      ...CLUSTER_PRIMARIO.clusterNodes![1],
      state: 'Self',
      configLastSynced: '2026-08-26T04:00:00Z',
    },
  ],
}
