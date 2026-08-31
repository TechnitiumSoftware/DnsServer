import type { OpcionesZona, PoliticaActualizacion } from '../../api/zones'
import { limpiarLista } from '../../api/zonelists'
import { serializarTabla } from '../../lib/tabla-serie'

/*
El formulario de `modalZoneOptions`: cinco pestañas, y **qué se ve y qué se
puede tocar depende del tipo de zona y de si pertenece a un catálogo**.

Réplica de `showZoneOptionsModal` (zone.js:1524-2380) y `saveZoneOptions`
(2380-2544). Son 856 líneas de jQuery encendiendo y apagando controles uno a
uno; aquí es una función pura que devuelve el estado, y se prueba sola.

La regla de fondo, que explica casi todo: **una zona miembro de un catálogo
hereda sus opciones**. Si el catálogo no le deja sobrescribir una sección, esa
pestaña DESAPARECE; si se la deja, aparece editable; y si además la administra
un catálogo secundario, aparece pero de sólo lectura, porque ni siquiera este
servidor manda sobre ella.
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

/* ── Estado de la interfaz ─────────────────────────────────────────────── */

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
  /** Los dos criterios «…Name Servers In Zone» no existen en algunos tipos. */
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

  // El servidor primario: las tres secundarias y la stub.
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
  La pestaña que sale abierta NO es siempre la primera: en una Catalog es
  «Query Access», y en una Primary o Forwarder depende de si hay catálogos
  disponibles (zone.js:2303-2360).
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
    // Las casillas de sobrescritura se apagan si la zona no está en un catálogo,
    // y también cuando la administra un catálogo secundario.
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
`\r\n` a propósito NO: upstream monta los textareas con `\r\n`, pero el
navegador normaliza al leerlos del DOM y su limpieza sólo sustituye `\n`. En
React no hay DOM intermedio, así que aquí se unen con `\n` y el resultado en el
servidor es idéntico. Está anotado en CONVENCIONES.md porque muerde a cualquier
pantalla con listas en textarea.
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
    // Un protocolo desconocido cae a TCP, igual que el `default` de upstream.
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
`serializeTableData` con 3 columnas para las políticas de actualización. El
algoritmo vive en `lib/tabla-serie`, compartido por las cinco pantallas con
tabla editable; aquí sólo se dice dónde está la celda que falla.
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
 * `saveZoneOptions` (zone.js:2380). Cuatro listas caen a la cadena `"false"`
 * cuando están vacías —`zoneTransferNetworkACL`, `zoneTransferTsigKeyNames`,
 * `notifyNameServers`, `notifySecondaryCatalogsNameServers`,
 * `updateNetworkACL` y `updateSecurityPolicies`— y **dos no**:
 * `primaryNameServerAddresses` y `queryAccessNetworkACL` viajan vacías tal cual.
 * No es simetría: es lo que hace upstream.
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

/** Qué criterios habilitan su lista de ACL: son los mismos cuatro en las cuatro secciones. */
export function aclEditable(valor: string): boolean {
  return (
    valor === 'UseSpecifiedNetworkACL' ||
    valor === 'AllowZoneNameServersAndUseSpecifiedNetworkACL'
  )
}

/** En Notify, la lista de servidores se habilita con tres de los cinco criterios. */
export function notificacionConLista(valor: string): boolean {
  return (
    valor === 'SpecifiedNameServers' ||
    valor === 'BothZoneAndSpecifiedNameServers' ||
    valor === 'SeparateNameServersForCatalogAndMemberZones'
  )
}
