import type { OpcionesZona, PoliticaActualizacion } from '../../api/zones'
import { limpiarLista } from '../../api/zonelists'
import { serializarTabla } from '../../lib/tabla-serie'

/*
The `modalZoneOptions` form: five tabs, and **what shows and what can be touched
depends on the zone type and on whether it belongs to a catalog**.

A replica of `showZoneOptionsModal` (zone.js:1524-2380) and `saveZoneOptions`
(2380-2544). Those are 856 lines of jQuery switching controls on and off one by
one; here it is a pure function that returns the state, and it tests on its own.

The underlying rule, which explains nearly everything: **a zone that is a member
of a catalog inherits its options**. If the catalog does not let it override a
section, that tab DISAPPEARS; if it does, it appears editable; and if on top of
that it is administered by a secondary catalog, it appears but read-only, because
not even this server rules over it.
*/

export type PestanaOpciones = 'General' | 'Query Access' | 'Zone Transfer' | 'Notify' | 'Dynamic Updates'

export const PESTANAS: { id: PestanaOpciones; etiqueta: string }[] = [
  { id: 'General', etiqueta: 'General' },
  { id: 'Query Access', etiqueta: 'Query Access' },
  { id: 'Zone Transfer', etiqueta: 'Zone Transfer' },
  { id: 'Notify', etiqueta: 'Notify' },
  { id: 'Dynamic Updates', etiqueta: 'Dynamic Updates (RFC 2136)' },
]

export const ACCESOS_CONSULTA = [
  { valor: 'Deny', etiqueta: 'Deny' },
  { valor: 'Allow', etiqueta: 'Allow (default)' },
  { valor: 'AllowOnlyPrivateNetworks', etiqueta: 'Allow Only Private Networks' },
  { valor: 'AllowOnlyZoneNameServers', etiqueta: 'Allow Only Name Servers In Zone' },
  { valor: 'UseSpecifiedNetworkACL', etiqueta: 'Use Specified Network Access Control List (ACL)' },
  {
    valor: 'AllowZoneNameServersAndUseSpecifiedNetworkACL',
    etiqueta: 'Allow Zone Name Servers And Use Specified Network Access Control List (ACL)',
  },
]

export const TRANSFERENCIAS = [
  { valor: 'Deny', etiqueta: 'Deny' },
  { valor: 'Allow', etiqueta: 'Allow' },
  { valor: 'AllowOnlyZoneNameServers', etiqueta: 'Allow Only Name Servers In Zone' },
  { valor: 'UseSpecifiedNetworkACL', etiqueta: 'Use Specified Network Access Control List (ACL)' },
  {
    valor: 'AllowZoneNameServersAndUseSpecifiedNetworkACL',
    etiqueta: 'Allow Zone Name Servers And Use Specified Network Access Control List (ACL)',
  },
]

export const NOTIFICACIONES = [
  { valor: 'None', etiqueta: 'None' },
  { valor: 'ZoneNameServers', etiqueta: 'Name Servers In Zone' },
  { valor: 'SpecifiedNameServers', etiqueta: 'Specified Name Servers' },
  { valor: 'BothZoneAndSpecifiedNameServers', etiqueta: 'Both Zone Name Servers And Specified Name Servers' },
  {
    valor: 'SeparateNameServersForCatalogAndMemberZones',
    etiqueta: 'Separate Name Servers For Catalog And Member Zones',
  },
]

export const ACTUALIZACIONES = [
  { valor: 'Deny', etiqueta: 'Deny (default)' },
  { valor: 'Allow', etiqueta: 'Allow' },
  { valor: 'AllowOnlyZoneNameServers', etiqueta: 'Allow Only Name Servers In Zone' },
  { valor: 'UseSpecifiedNetworkACL', etiqueta: 'Use Specified Network Access Control List (ACL)' },
  {
    valor: 'AllowZoneNameServersAndUseSpecifiedNetworkACL',
    etiqueta: 'Allow Zone Name Servers And Use Specified Network Access Control List (ACL)',
  },
]

export const PROTOCOLOS_XFR = [
  { valor: 'Tcp', etiqueta: 'XFR-over-TCP (default)' },
  { valor: 'Tls', etiqueta: 'XFR-over-TLS' },
  { valor: 'Quic', etiqueta: 'XFR-over-QUIC' },
]

/* ── Interface state ───────────────────────────────────────────────────── */

export interface EstadoOpciones {
  pestanas: PestanaOpciones[]
  pestanaInicial: PestanaOpciones
  /** General */
  catalogo: boolean
  catalogoFijo: boolean
  sobrescribirQueryAccess: boolean
  sobrescribirZoneTransfer: boolean
  sobrescribirNotify: boolean
  sobrescribirBloqueado: boolean
  servidorPrimario: boolean
  servidorPrimarioObligatorio: boolean
  protocoloXfr: boolean
  tsigDelPrimario: boolean
  validarZona: boolean
  servidorPrimarioBloqueado: boolean
  /** Query Access */
  queryAccessBloqueado: boolean
  /** The two "…Name Servers In Zone" criteria do not exist on some types. */
  queryAccessConNameServers: boolean
  /** Zone Transfer */
  zoneTransferBloqueado: boolean
  zoneTransferConNameServers: boolean
  /** Notify */
  notifyConNameServers: boolean
  notifySeparados: boolean
  /** Dynamic Updates */
  updateConNameServers: boolean
  politicasDeSeguridad: boolean
}

const SECUNDARIAS = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog']

export function estadoOpciones(r: OpcionesZona): EstadoOpciones {
  const tipo = r.type
  const enCatalogo = r.catalog != null
  const miembroSecundario = enCatalogo && r.isSecondaryCatalogMember === true
  const catalogosDisponibles = (r.availableCatalogZoneNames ?? []).length > 0

  const pestanas: PestanaOpciones[] = []

  /* ── General ──────────────────────────────────────────────────────── */
  let catalogo = false
  let catalogoFijo = false
  let sobrescribirQueryAccess = false
  let sobrescribirZoneTransfer = false
  let sobrescribirNotify = false

  switch (tipo) {
    case 'Primary':
    case 'Forwarder':
      if (catalogosDisponibles) {
        catalogo = true
        sobrescribirQueryAccess = true
        sobrescribirZoneTransfer = true
        sobrescribirNotify = true
      }
      break

    case 'Stub':
      if (miembroSecundario) {
        catalogo = true
        catalogoFijo = true
        sobrescribirQueryAccess = true
      } else if (catalogosDisponibles) {
        catalogo = true
        sobrescribirQueryAccess = true
      }
      break

    case 'Secondary':
      if (miembroSecundario) {
        catalogo = true
        catalogoFijo = true
        sobrescribirQueryAccess = true
        sobrescribirZoneTransfer = true
      } else if (catalogosDisponibles) {
        catalogo = true
        sobrescribirQueryAccess = true
        sobrescribirZoneTransfer = true
      }
      break

    case 'SecondaryForwarder':
      if (enCatalogo) {
        catalogo = true
        catalogoFijo = true
        sobrescribirQueryAccess = true
      }
      break
  }

  // The primary server: the three secondaries and the stub.
  let servidorPrimario = false
  let protocoloXfr = false
  let tsigDelPrimario = false
  let validarZona = false
  let servidorPrimarioObligatorio = false

  if (SECUNDARIAS.includes(tipo)) {
    protocoloXfr = true
    tsigDelPrimario = true
    validarZona = tipo === 'Secondary'
    servidorPrimarioObligatorio = tipo === 'SecondaryForwarder' || tipo === 'SecondaryCatalog'

    servidorPrimario =
      tipo === 'Secondary' || tipo === 'SecondaryForwarder'
        ? !enCatalogo || r.overrideCatalogPrimaryNameServers === true
        : true
  } else if (tipo === 'Stub') {
    servidorPrimario = true
  }

  if (catalogo || servidorPrimario) pestanas.push('General')

  /* ── Query Access ─────────────────────────────────────────────────── */
  let queryAccess = false
  let queryAccessBloqueado = false

  switch (tipo) {
    case 'Primary':
    case 'Forwarder':
    case 'Catalog':
      queryAccess = !enCatalogo || r.overrideCatalogQueryAccess === true
      break

    case 'Stub':
      if (miembroSecundario) {
        queryAccess = r.overrideCatalogQueryAccess === true
        queryAccessBloqueado = true
      } else {
        queryAccess = !enCatalogo || r.overrideCatalogQueryAccess === true
      }
      break

    case 'Secondary':
    case 'SecondaryForwarder':
      queryAccess = !enCatalogo || r.overrideCatalogQueryAccess === true
      queryAccessBloqueado = enCatalogo
      break

    case 'SecondaryCatalog':
      queryAccess = true
      queryAccessBloqueado = true
      break
  }

  if (queryAccess) pestanas.push('Query Access')

  /* ── Zone Transfer ────────────────────────────────────────────────── */
  let zoneTransfer = false
  let zoneTransferBloqueado = false

  switch (tipo) {
    case 'Primary':
    case 'Forwarder':
      zoneTransfer = !enCatalogo || r.overrideCatalogZoneTransfer === true
      break

    case 'Secondary':
      zoneTransfer = !enCatalogo || r.overrideCatalogZoneTransfer === true
      zoneTransferBloqueado = enCatalogo
      break

    case 'Catalog':
      zoneTransfer = true
      break

    case 'SecondaryCatalog':
      zoneTransfer = true
      zoneTransferBloqueado = true
      break
  }

  if (zoneTransfer) pestanas.push('Zone Transfer')

  /* ── Notify ───────────────────────────────────────────────────────── */
  let notify = false
  switch (tipo) {
    case 'Primary':
    case 'Forwarder':
      notify = !enCatalogo || r.overrideCatalogNotify === true
      break
    case 'Secondary':
    case 'Catalog':
      notify = true
      break
  }
  if (notify) pestanas.push('Notify')

  /* ── Dynamic Updates ──────────────────────────────────────────────── */
  const update = ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder'].includes(tipo)
  if (update) pestanas.push('Dynamic Updates')

  /*
  The tab that comes up open is NOT always the first: on a Catalog it is "Query
  Access", and on a Primary or Forwarder it depends on whether there are catalogs
  available (zone.js:2303-2360).
  */
  let inicial: PestanaOpciones = pestanas[0] ?? 'Query Access'
  if ([...SECUNDARIAS, 'Stub'].includes(tipo)) inicial = 'General'
  else if (tipo === 'Catalog') inicial = 'Query Access'
  else if (tipo === 'Primary' || tipo === 'Forwarder') {
    inicial = catalogosDisponibles ? 'General' : 'Query Access'
  }

  return {
    pestanas,
    pestanaInicial: pestanas.includes(inicial) ? inicial : (pestanas[0] ?? 'Query Access'),
    catalogo,
    catalogoFijo,
    sobrescribirQueryAccess,
    sobrescribirZoneTransfer,
    sobrescribirNotify,
    // The override checkboxes go off if the zone is not in a catalog,
    // and also when it is administered by a secondary catalog.
    sobrescribirBloqueado: !enCatalogo || miembroSecundario,
    servidorPrimario,
    servidorPrimarioObligatorio,
    protocoloXfr,
    tsigDelPrimario,
    validarZona,
    servidorPrimarioBloqueado: miembroSecundario,
    queryAccessBloqueado,
    queryAccessConNameServers: !['Stub', 'Forwarder', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog'].includes(tipo),
    zoneTransferBloqueado,
    zoneTransferConNameServers: !['Forwarder', 'Catalog', 'SecondaryCatalog'].includes(tipo),
    notifyConNameServers: tipo !== 'Forwarder' && tipo !== 'Catalog',
    notifySeparados: tipo === 'Catalog',
    updateConNameServers: !['Secondary', 'SecondaryForwarder', 'Forwarder'].includes(tipo),
    politicasDeSeguridad: tipo === 'Primary' || tipo === 'Forwarder',
  }
}

/* ── El formulario ─────────────────────────────────────────────────────── */

export interface FilaPolitica {
  tsigKeyName: string
  domain: string
  allowedTypes: string
}

export interface FormularioOpciones {
  catalog: string
  overrideCatalogQueryAccess: boolean
  overrideCatalogZoneTransfer: boolean
  overrideCatalogNotify: boolean
  primaryNameServerAddresses: string
  primaryZoneTransferProtocol: string
  primaryZoneTransferTsigKeyName: string
  validateZone: boolean
  queryAccess: string
  queryAccessNetworkACL: string
  zoneTransfer: string
  zoneTransferNetworkACL: string
  zoneTransferTsigKeyNames: string
  notify: string
  notifyNameServers: string
  notifySecondaryCatalogsNameServers: string
  update: string
  updateNetworkACL: string
  updateSecurityPolicies: FilaPolitica[]
}

/*
No `\r\n` on purpose: upstream builds the textareas with `\r\n`, but the browser
normalises when reading them from the DOM and its cleanup only substitutes `\n`.
In React there is no intermediate DOM, so here they are joined with `\n` and the
result on the server is identical. It is noted in CONVENCIONES.md because it
bites any screen with lists in a textarea.
*/
function texto(lista: readonly string[] | null | undefined): string {
  return (lista ?? []).join('\n')
}

export function formularioDesdeOpciones(r: OpcionesZona): FormularioOpciones {
  return {
    catalog: r.catalog ?? '',
    overrideCatalogQueryAccess: r.catalog != null && r.overrideCatalogQueryAccess === true,
    overrideCatalogZoneTransfer: r.catalog != null && r.overrideCatalogZoneTransfer === true,
    overrideCatalogNotify: r.catalog != null && r.overrideCatalogNotify === true,
    primaryNameServerAddresses: texto(r.primaryNameServerAddresses),
    // An unknown protocol falls to TCP, just like upstream's `default`.
    primaryZoneTransferProtocol:
      r.primaryZoneTransferProtocol === 'Tls' || r.primaryZoneTransferProtocol === 'Quic'
        ? r.primaryZoneTransferProtocol
        : 'Tcp',
    primaryZoneTransferTsigKeyName: r.primaryZoneTransferTsigKeyName ?? '',
    validateZone: r.validateZone === true,
    queryAccess: r.queryAccess ?? 'Deny',
    queryAccessNetworkACL: texto(r.queryAccessNetworkACL),
    zoneTransfer: r.zoneTransfer ?? 'Deny',
    zoneTransferNetworkACL: texto(r.zoneTransferNetworkACL),
    zoneTransferTsigKeyNames: texto(r.zoneTransferTsigKeyNames),
    notify: r.notify ?? 'None',
    notifyNameServers: texto(r.notifyNameServers),
    notifySecondaryCatalogsNameServers: texto(r.notifySecondaryCatalogsNameServers),
    update: r.update ?? 'Deny',
    updateNetworkACL: texto(r.updateNetworkACL),
    updateSecurityPolicies: (r.updateSecurityPolicies ?? []).map(filaDesdePolitica),
  }
}

function filaDesdePolitica(p: PoliticaActualizacion): FilaPolitica {
  return {
    tsigKeyName: p.tsigKeyName,
    domain: p.domain,
    allowedTypes: (p.allowedTypes ?? []).join(', '),
  }
}

export interface ErrorOpciones {
  title: string
  text: string
  tab: PestanaOpciones
  campo: keyof FormularioOpciones
}

export type ResultadoOpciones = { error: ErrorOpciones } | { body: Record<string, string> }

/*
`serializeTableData` with 3 columns for the update policies. The algorithm lives
in `lib/tabla-serie`, shared by the five screens with an editable table; all that
is said here is where the failing cell is.
*/
function serializarPoliticas(
  filas: FilaPolitica[],
): { valor: string } | { error: ErrorOpciones } {
  const r = serializarTabla(
    filas.map((fila) =>
      [fila.tsigKeyName, fila.domain, fila.allowedTypes].map((valor) => ({
        tipo: 'texto' as const,
        valor,
      })),
    ),
  )
  if (r.ok) return { valor: r.valor }
  return {
    error: {
      title: r.fallo.title,
      text: r.fallo.text,
      tab: 'Dynamic Updates',
      campo: 'updateSecurityPolicies',
    },
  }
}

/**
 * `saveZoneOptions` (zone.js:2380). Four lists fall to the string `"false"` when
 * empty —`zoneTransferNetworkACL`, `zoneTransferTsigKeyNames`,
 * `notifyNameServers`, `notifySecondaryCatalogsNameServers`, `updateNetworkACL`
 * and `updateSecurityPolicies`— and **two do not**:
 * `primaryNameServerAddresses` and `queryAccessNetworkACL` travel empty as they
 * are. It is not symmetry: it is what upstream does.
 */
export function construirCuerpoOpciones(
  f: FormularioOpciones,
  tipoZona: string,
): ResultadoOpciones {
  if (tipoZona === 'SecondaryForwarder' || tipoZona === 'SecondaryCatalog') {
    const direcciones = limpiarLista(f.primaryNameServerAddresses)
    if (direcciones.length === 0 || direcciones === ',') {
      return {
        error: {
          title: 'Missing!',
          text: 'Please enter at least one primary name server address to proceed.',
          tab: 'General',
          campo: 'primaryNameServerAddresses',
        },
      }
    }
  }

  const vacioEsFalso = (v: string): string => {
    const limpio = limpiarLista(v)
    return limpio.length === 0 || limpio === ',' ? 'false' : limpio
  }

  const politicas = serializarPoliticas(f.updateSecurityPolicies)
  if ('error' in politicas) return politicas

  return {
    body: {
      catalog: f.catalog,
      overrideCatalogQueryAccess: String(f.overrideCatalogQueryAccess),
      overrideCatalogZoneTransfer: String(f.overrideCatalogZoneTransfer),
      overrideCatalogNotify: String(f.overrideCatalogNotify),
      primaryNameServerAddresses: limpiarLista(f.primaryNameServerAddresses),
      primaryZoneTransferProtocol: f.primaryZoneTransferProtocol,
      primaryZoneTransferTsigKeyName: f.primaryZoneTransferTsigKeyName,
      validateZone: String(f.validateZone),
      queryAccess: f.queryAccess,
      queryAccessNetworkACL: limpiarLista(f.queryAccessNetworkACL),
      zoneTransfer: f.zoneTransfer,
      zoneTransferNetworkACL: vacioEsFalso(f.zoneTransferNetworkACL),
      zoneTransferTsigKeyNames: vacioEsFalso(f.zoneTransferTsigKeyNames),
      notify: f.notify,
      notifyNameServers: vacioEsFalso(f.notifyNameServers),
      notifySecondaryCatalogsNameServers: vacioEsFalso(f.notifySecondaryCatalogsNameServers),
      update: f.update,
      updateNetworkACL: vacioEsFalso(f.updateNetworkACL),
      updateSecurityPolicies: politicas.valor.length === 0 ? 'false' : politicas.valor,
    },
  }
}

/** Which criteria enable their ACL list: the same four in all four sections. */
export function aclEditable(valor: string): boolean {
  return (
    valor === 'UseSpecifiedNetworkACL' ||
    valor === 'AllowZoneNameServersAndUseSpecifiedNetworkACL'
  )
}

/** In Notify, the server list is enabled by three of the five criteria. */
export function notificacionConLista(valor: string): boolean {
  return (
    valor === 'SpecifiedNameServers' ||
    valor === 'BothZoneAndSpecifiedNameServers' ||
    valor === 'SeparateNameServersForCatalogAndMemberZones'
  )
}
