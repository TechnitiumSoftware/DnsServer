/*
The console's 12 sections, in upstream's order.

`permission` is the key inside `sessionData.info.permissions`, and it does NOT
always match the label: the "DNS Client" tab is governed by `DnsClient` and "DHCP"
by `DhcpServer`. `About` has no permission: it is always visible.

Each section is hidden if its `canView` is false (main.js:119-250). `phase` records
which phase each one came out of; with phases 4, 8 and 9 closed there is none left
unimplemented.
*/
export interface Section {
  id: string
  label: string
  permission: string | null
  phase: string
  /** Sub-sections, with upstream's literal labels. They are only shown when their
   *  section is active, exactly as the sub-tabs are today. */
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
