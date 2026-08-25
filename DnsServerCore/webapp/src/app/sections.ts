/*
Las 12 secciones de la consola, en el orden de upstream.

`permission` es la clave dentro de `sessionData.info.permissions`, y NO siempre
coincide con la etiqueta: la pestaña «DNS Client» se gobierna con `DnsClient` y
«DHCP» con `DhcpServer`. `About` no tiene permiso: se ve siempre.

Cada sección se oculta si su `canView` es falso (main.js:119-250), y la fase que
la implementa está anotada para que quede claro qué falta.
*/
export interface Section {
  id: string
  label: string
  permission: string | null
  phase: string
  /** Sub-secciones, con sus etiquetas literales de upstream. Sólo se muestran
   *  cuando su sección está activa, igual que hoy las sub-pestañas. */
  subs?: string[]
}

export const SECTIONS: Section[] = [
  { id: 'dashboard', label: 'Dashboard', permission: 'Dashboard', phase: 'fase 3' },
  { id: 'zones', label: 'Zones', permission: 'Zones', phase: 'fase 4' },
  { id: 'cache', label: 'Cache', permission: 'Cache', phase: 'fase 5' },
  { id: 'allowed', label: 'Allowed', permission: 'Allowed', phase: 'fase 5' },
  { id: 'blocked', label: 'Blocked', permission: 'Blocked', phase: 'fase 5' },
  { id: 'apps', label: 'Apps', permission: 'Apps', phase: 'fase 7' },
  { id: 'dnsclient', label: 'DNS Client', permission: 'DnsClient', phase: 'fase 3' },
  { id: 'settings', label: 'Settings', permission: 'Settings', phase: 'fase 6',
    subs: ['General','Web Service','Optional Protocols','TSIG','Recursion','Cache','Blocking','Proxy & Forwarders','Logging'] },
  { id: 'dhcp', label: 'DHCP', permission: 'DhcpServer', phase: 'fase 8', subs: ['Leases','Scopes'] },
  { id: 'admin', label: 'Administration', permission: 'Administration', phase: 'fase 9',
    subs: ['Sessions','Users','Groups','Permissions','SSO','Cluster'] },
  { id: 'logs', label: 'Logs', permission: 'Logs', phase: 'fase 8', subs: ['View Logs','Query Logs'] },
  { id: 'about', label: 'About', permission: null, phase: 'fase 3' },
]

export interface Permission { canView: boolean; canModify: boolean; canDelete: boolean }

export function visibleSections(permissions: Record<string, Permission> | undefined): Section[] {
  if (!permissions) return SECTIONS
  return SECTIONS.filter((s) => s.permission == null || permissions[s.permission]?.canView !== false)
}
