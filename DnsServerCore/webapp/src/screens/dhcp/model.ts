import type { DhcpScope } from '../../api/dhcp'
import { serializeTable } from '../../lib/table-serialise'

/*
The form of a DHCP scope: 36 fields, five of them editable tables.

Everything upstream validates before saving is in `serializeTableData`
(common.js:282-324). There is no other client-side check: the rest is rejected by
the server. That function is replicated here as it stands, including:

  · the ORDER — cell by cell, row by row, and the five tables in the order
    `saveDhcpScope` serialises them: static routes, vendor information, generic
    options, exclusions and reservations (dhcp.js:525-547). The two text lists
    read in between (CAPWAP and TFTP) validate nothing;
  · the TWO alerts, with their literal texts and in their order: "empty" first,
    "forbidden character" second;
  · which cells are OPTIONAL (`data-optional="true"`): the vendor identifier, and
    a reservation's host name and comments. No other one may be left empty.

One upstream detail that is NOT replicated here, on purpose: `serializeTableData`
applies `htmlDecode` to the value it has just read from the DOM, where the
browser had ALREADY decoded it when parsing the HTML. It is a second decoding
over already-clean text: typing `&amp;` into a cell sends it to the server as
`&`. In React there is no intermediate HTML, so the value travels exactly as
typed. Replicating the double decoding would be introducing the bug by hand.
*/

export interface StaticRouteRow {
  destination: string
  subnetMask: string
  router: string
}
export interface VendorInfoRow {
  identifier: string
  information: string
}
export interface GenericOptionRow {
  code: string
  value: string
}
export interface ExclusionRow {
  startingAddress: string
  endingAddress: string
}
export interface ReservationRow {
  hostName: string
  hardwareAddress: string
  address: string
  comments: string
}

export interface ScopeForm {
  /** The `data-name` of the Name field: the name the scope was loaded with.
   *  Empty on a new scope. It is what decides whether there is a rename. */
  oldName: string
  name: string
  startingAddress: string
  endingAddress: string
  subnetMask: string
  leaseTimeDays: string
  leaseTimeHours: string
  leaseTimeMinutes: string
  offerDelayTime: string
  pingCheckEnabled: boolean
  pingCheckTimeout: string
  pingCheckRetries: string
  domainName: string
  domainSearchList: string
  dnsUpdates: boolean
  dnsOverwriteForDynamicLease: boolean
  dnsTtl: string
  serverAddress: string
  serverHostName: string
  bootFileName: string
  routerAddress: string
  useThisDnsServer: boolean
  dnsServers: string
  winsServers: string
  ntpServers: string
  ntpServerDomainNames: string
  staticRoutes: StaticRouteRow[]
  vendorInfo: VendorInfoRow[]
  capwapAcIpAddresses: string
  tftpServerAddresses: string
  genericOptions: GenericOptionRow[]
  exclusions: ExclusionRow[]
  reservedLeases: ReservationRow[]
  allowOnlyReservedLeases: boolean
  blockLocallyAdministeredMacAddresses: boolean
  ignoreClientIdentifierOption: boolean
}

/** `clearDhcpScopeForm` (dhcp.js:310). The default values are upstream's, not
 *  choices of ours: a 1-day lease, ping check at 1000 ms with 2 retries, DNS TTL
 *  of 900 s, DNS updates checked and client identifier ignored. */
export function emptyForm(): ScopeForm {
  return {
    oldName: '',
    name: '',
    startingAddress: '',
    endingAddress: '',
    subnetMask: '',
    leaseTimeDays: '1',
    leaseTimeHours: '0',
    leaseTimeMinutes: '0',
    offerDelayTime: '0',
    pingCheckEnabled: false,
    pingCheckTimeout: '1000',
    pingCheckRetries: '2',
    domainName: '',
    domainSearchList: '',
    dnsUpdates: true,
    dnsOverwriteForDynamicLease: false,
    dnsTtl: '900',
    serverAddress: '',
    serverHostName: '',
    bootFileName: '',
    routerAddress: '',
    useThisDnsServer: false,
    dnsServers: '',
    winsServers: '',
    ntpServers: '',
    ntpServerDomainNames: '',
    staticRoutes: [],
    vendorInfo: [],
    capwapAcIpAddresses: '',
    tftpServerAddresses: '',
    genericOptions: [],
    exclusions: [],
    reservedLeases: [],
    allowOnlyReservedLeases: false,
    blockLocallyAdministeredMacAddresses: false,
    ignoreClientIdentifierOption: true,
  }
}

/** `showAddDhcpScope` (dhcp.js:352) starts from the empty form but checks
 *  "Use This DNS Server", which in turn disables the DNS servers area. */
export function formularioNuevo(): ScopeForm {
  return { ...emptyForm(), useThisDnsServer: true }
}

/** An array of strings into a textarea, with a newline between items
 *  (`.join("\n")`, dhcp.js:399 and following). */
export function listToText(list: string[] | undefined): string {
  return list == null ? '' : list.join('\n')
}

/** `cleanTextList` (common.js:326): newlines to commas, repeated commas
 *  collapsed and no commas at the ends. */
export function cleanList(text: string): string {
  let t = text.replace(/\n/g, ',')
  while (t.includes(',,')) t = t.replace(/,,/g, ',')
  if (t.startsWith(',')) t = t.substring(1)
  if (t.endsWith(',')) t = t.substring(0, t.length - 1)
  return t
}

/** `showEditDhcpScope` (dhcp.js:363). The fields the server OMITS when they are
 *  null stay as they were in the empty form. */
export function formularioDesdeScope(s: DhcpScope): ScopeForm {
  const f = emptyForm()
  return {
    ...f,
    oldName: s.name,
    name: s.name,
    startingAddress: s.startingAddress,
    endingAddress: s.endingAddress,
    subnetMask: s.subnetMask,
    leaseTimeDays: String(s.leaseTimeDays),
    leaseTimeHours: String(s.leaseTimeHours),
    leaseTimeMinutes: String(s.leaseTimeMinutes),
    offerDelayTime: String(s.offerDelayTime),
    pingCheckEnabled: s.pingCheckEnabled,
    pingCheckTimeout: String(s.pingCheckTimeout),
    pingCheckRetries: String(s.pingCheckRetries),
    domainName: s.domainName ?? '',
    domainSearchList: listToText(s.domainSearchList),
    dnsUpdates: s.dnsUpdates,
    dnsOverwriteForDynamicLease: s.dnsOverwriteForDynamicLease,
    dnsTtl: String(s.dnsTtl),
    serverAddress: s.serverAddress ?? '',
    serverHostName: s.serverHostName ?? '',
    bootFileName: s.bootFileName ?? '',
    routerAddress: s.routerAddress ?? '',
    useThisDnsServer: s.useThisDnsServer,
    dnsServers: listToText(s.dnsServers),
    winsServers: listToText(s.winsServers),
    ntpServers: listToText(s.ntpServers),
    ntpServerDomainNames: listToText(s.ntpServerDomainNames),
    staticRoutes: (s.staticRoutes ?? []).map((r) => ({
      destination: r.destination,
      subnetMask: r.subnetMask,
      router: r.router,
    })),
    vendorInfo: (s.vendorInfo ?? []).map((v) => ({
      identifier: v.identifier,
      information: v.information,
    })),
    capwapAcIpAddresses: listToText(s.capwapAcIpAddresses),
    tftpServerAddresses: listToText(s.tftpServerAddresses),
    genericOptions: (s.genericOptions ?? []).map((o) => ({
      code: String(o.code),
      value: o.value,
    })),
    exclusions: (s.exclusions ?? []).map((e) => ({
      startingAddress: e.startingAddress,
      endingAddress: e.endingAddress,
    })),
    reservedLeases: (s.reservedLeases ?? []).map((r) => ({
      hostName: r.hostName ?? '',
      hardwareAddress: r.hardwareAddress,
      address: r.address,
      comments: r.comments ?? '',
    })),
    allowOnlyReservedLeases: s.allowOnlyReservedLeases,
    blockLocallyAdministeredMacAddresses: s.blockLocallyAdministeredMacAddresses,
    ignoreClientIdentifierOption: s.ignoreClientIdentifierOption,
  }
}

export interface ScopeError {
  title: string
  text: string
  /** `id` of the control upstream focuses. The alert's text talks about "the text
   *  field in focus", so without this the alert cannot be resolved. */
  focus: string
}

/** The `id` of a table cell. Deterministic so it can be focused. */
export function cellId(table: string, row: number, column: string): string {
  return `dhcp-${table}-${row}-${column}`
}

/*
`serializeTableData` (common.js:282). Returns the cells of every row joined by
`|`, or the alert of the first cell that is not valid.
*/
function serialize(
  table: string,
  rows: Record<string, string>[],
  columns: { key: string; optional?: boolean }[],
): { value: string } | { error: ScopeError } {
  /*
  The algorithm is upstream's `serializeTableData` and it lives in
  `lib/tabla-serie`, shared by the five screens with an editable table. All that
  is translated here is where the failing cell is: in DHCP, to that cell's
  deterministic `id`, because the alert literally says "the text field in focus"
  and without being able to focus it there is no resolving it.
  */
  const r = serializeTable(
    rows.map((row) =>
      columns.map((col) => ({
        type: 'text' as const,
        value: row[col.key] ?? '',
        optional: col.optional,
      })),
    ),
  )
  if (r.ok) return { value: r.value }
  return {
    error: {
      title: r.failure.title,
      text: r.failure.text,
      focus: cellId(table, r.failure.row, columns[r.failure.column].key),
    },
  }
}

/*
`saveDhcpScope` (dhcp.js:485). Builds the POST body in the same order and with
the same rules:

  · if the scope already existed and the name changed, `name` carries the OLD one
    and `newName` appears with the new one;
  · `dnsServers` is not sent if "Use This DNS Server" is checked;
  · the five tables are validated in the order they are serialised, and the first
    failure aborts the save.
*/
export function buildBody(
  f: ScopeForm,
): { body: Record<string, string> } | { error: ScopeError } {
  let name = f.name
  let newName: string | null = null

  if (f.oldName !== '' && f.oldName !== name) {
    newName = name
    name = f.oldName
  }

  const staticRoutes = serialize('staticRoutes', f.staticRoutes as unknown as Record<string, string>[], [
    { key: 'destination' },
    { key: 'subnetMask' },
    { key: 'router' },
  ])
  if ('error' in staticRoutes) return staticRoutes

  const vendorInfo = serialize('vendorInfo', f.vendorInfo as unknown as Record<string, string>[], [
    { key: 'identifier', optional: true },
    { key: 'information' },
  ])
  if ('error' in vendorInfo) return vendorInfo

  const genericOptions = serialize(
    'genericOptions',
    f.genericOptions as unknown as Record<string, string>[],
    [{ key: 'code' }, { key: 'value' }],
  )
  if ('error' in genericOptions) return genericOptions

  const exclusions = serialize('exclusions', f.exclusions as unknown as Record<string, string>[], [
    { key: 'startingAddress' },
    { key: 'endingAddress' },
  ])
  if ('error' in exclusions) return exclusions

  const reservedLeases = serialize(
    'reservedLeases',
    f.reservedLeases as unknown as Record<string, string>[],
    [
      { key: 'hostName', optional: true },
      { key: 'hardwareAddress' },
      { key: 'address' },
      { key: 'comments', optional: true },
    ],
  )
  if ('error' in reservedLeases) return reservedLeases

  const body: Record<string, string> = { name }
  if (newName !== null) body.newName = newName

  body.startingAddress = f.startingAddress
  body.endingAddress = f.endingAddress
  body.subnetMask = f.subnetMask
  body.leaseTimeDays = f.leaseTimeDays
  body.leaseTimeHours = f.leaseTimeHours
  body.leaseTimeMinutes = f.leaseTimeMinutes
  body.offerDelayTime = f.offerDelayTime
  body.pingCheckEnabled = String(f.pingCheckEnabled)
  body.pingCheckTimeout = f.pingCheckTimeout
  body.pingCheckRetries = f.pingCheckRetries
  body.domainName = f.domainName
  body.domainSearchList = cleanList(f.domainSearchList)
  body.dnsUpdates = String(f.dnsUpdates)
  body.dnsOverwriteForDynamicLease = String(f.dnsOverwriteForDynamicLease)
  body.dnsTtl = f.dnsTtl
  body.serverAddress = f.serverAddress
  body.serverHostName = f.serverHostName
  body.bootFileName = f.bootFileName
  body.routerAddress = f.routerAddress
  body.useThisDnsServer = String(f.useThisDnsServer)
  if (!f.useThisDnsServer) body.dnsServers = cleanList(f.dnsServers)
  body.winsServers = cleanList(f.winsServers)
  body.ntpServers = cleanList(f.ntpServers)
  body.ntpServerDomainNames = cleanList(f.ntpServerDomainNames)
  body.staticRoutes = staticRoutes.value
  body.vendorInfo = vendorInfo.value
  body.capwapAcIpAddresses = cleanList(f.capwapAcIpAddresses)
  body.tftpServerAddresses = cleanList(f.tftpServerAddresses)
  body.genericOptions = genericOptions.value
  body.exclusions = exclusions.value
  body.reservedLeases = reservedLeases.value
  body.allowOnlyReservedLeases = String(f.allowOnlyReservedLeases)
  body.blockLocallyAdministeredMacAddresses = String(f.blockLocallyAdministeredMacAddresses)
  body.ignoreClientIdentifierOption = String(f.ignoreClientIdentifierOption)

  return { body }
}
