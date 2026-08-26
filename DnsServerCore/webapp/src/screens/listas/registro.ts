import type { RegistroDns } from '../../api/zonelists'

/*
De JSON en crudo a filas de tabla.

Upstream vuelca `JSON.stringify(records, null, 2)` dentro de un `<pre>`
(other-zones.js:157, 335, 471). Aquí se pinta como tabla, y eso obliga a una
regla: **ni un campo del JSON puede desaparecer por el camino**. Por eso nada
aquí lleva una lista blanca de tipos de registro. Se recorren las claves que
vengan, se les da un nombre legible, y lo que no se reconozca sale igualmente
con su nombre humanizado. Si mañana el servidor añade un campo o un tipo de
registro nuevo, aparece solo.

Tres pares de claves que el servidor emite juntas y que se funden en una línea
para no repetir el mismo dato dos veces (WebServiceZonesApi.cs:68-860):

  `algorithm` + `algorithmNumber`   -> «RSASHA256 (8)»
  `refresh`   + `refreshString`     -> «900 (15m)»
  `nameServer`+ `nameServerIdn`     -> «mañana.test (xn--maana-pta.test)»
*/

export interface Entrada {
  clave: string
  valor: string
  /** Una clave pública de DNSKEY revienta el ancho: la pantalla la trunca. */
  largo: boolean
}

const LARGO = 64

/** Nombres que upstream y el diseño usan y que no salen de humanizar la clave. */
const ETIQUETAS: Record<string, string> = {
  ipAddress: 'IP Address',
  nameServer: 'Name Server',
  cname: 'CNAME',
  dname: 'DNAME',
  ptrName: 'PTR Name',
  primaryNameServer: 'Primary NS',
  responsiblePerson: 'Responsible',
  publicKey: 'Public key',
  keyTag: 'Key tag',
  computedKeyTag: 'Key tag',
  eDnsClientSubnet: 'EDNS Client Subnet',
  rdata: 'Data',
  uri: 'URI',
  svcPriority: 'SvcPriority',
  targetName: 'Target Name',
}

/** `algorithmNumber` -> «Algorithm number»; `flags` -> «Flags». */
function humanizar(clave: string): string {
  if (ETIQUETAS[clave]) return ETIQUETAS[clave]
  const palabras = clave
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
  return palabras.charAt(0).toUpperCase() + palabras.slice(1)
}

function texto(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') return String(v)
  return JSON.stringify(v)
}

function entrada(clave: string, valor: string): Entrada {
  return { clave, valor, largo: valor.length > LARGO }
}

const SUFIJOS = ['String', 'Number', 'Idn'] as const

/**
 * Convierte un objeto plano en filas clave/valor, fundiendo los pares
 * `x`/`xString`, `x`/`xNumber` y `x`/`xIdn`.
 */
function filas(obj: Record<string, unknown>): Entrada[] {
  const salida: Entrada[] = []

  for (const clave of Object.keys(obj)) {
    // Las claves derivadas se pintan junto a su base, no por su cuenta.
    const derivada = SUFIJOS.some(
      (s) => clave.endsWith(s) && clave.length > s.length && clave.slice(0, -s.length) in obj,
    )
    if (derivada) continue

    let valor = texto(obj[clave])

    const idn = obj[`${clave}Idn`]
    if (idn != null) {
      // El Unicode es lo legible; el ASCII es lo que viaja por el cable.
      valor = `${texto(idn)} (${valor})`
    } else {
      const compuesto = obj[`${clave}String`] ?? obj[`${clave}Number`]
      if (compuesto != null) valor = `${valor} (${texto(compuesto)})`
    }

    salida.push(entrada(humanizar(clave), valor))
  }

  return salida
}

export function entradasRData(rData: Record<string, unknown>): Entrada[] {
  return filas(rData ?? {})
}

/*
El TTL llega de dos formas distintas según la lista (ver `zonelists.ts`). Se
normaliza al par que pide el diseño: el número, y su forma humana al lado.
*/
export function ttlPartido(r: RegistroDns): { valor: string; humano: string } {
  if (typeof r.ttl === 'string') {
    const m = /^(\S+)\s+\((.*)\)$/.exec(r.ttl)
    return m ? { valor: m[1], humano: m[2] } : { valor: r.ttl, humano: '' }
  }
  return { valor: String(r.ttl), humano: r.ttlString ?? '' }
}

/*
`0001-01-01T00:00:00` es el `default(DateTime)` de .NET: significa «nunca», no
una fecha del año 1. Y se recorta a minutos SIN convertir de huso, porque el
servidor emite UTC y convertir sería cambiar el dato; la marca completa se
conserva en el `title` de la celda.
*/
export function fechaCorta(iso: string | undefined | null): string | null {
  if (!iso || iso.startsWith('0001-01-01')) return null
  return iso.slice(0, 16).replace('T', ' ')
}

/*
La línea gris de cada fila. En cache lleva por dónde vino el registro; en
allowed y blocked, el estado del registro en la zona.
*/
export function meta(r: RegistroDns): string[] {
  const partes: string[] = []

  if (r.disabled) partes.push('disabled')

  const rm = r.responseMetadata
  if (rm) {
    partes.push(`via ${rm.nameServer ?? '—'}`)
    if (rm.protocol) partes.push(rm.protocol)
    if (rm.datagramSize) partes.push(rm.datagramSize)
    if (rm.roundTripTime) partes.push(rm.roundTripTime)
  } else if (r.dnssecStatus) {
    // En cache el estado DNSSEC tiene columna propia; aquí no, así que va aquí.
    partes.push(`DNSSEC ${r.dnssecStatus}`)
  }

  // El vocabulario es el de upstream: «Last Modified», «Last Used» y «(never)»
  // (zone.js:4179-4188), aquí en una sola línea en vez de en tres.
  const modificado = fechaCorta(r.lastModified)
  if (modificado) partes.push(`modified ${modificado}`)

  const usado = fechaCorta(r.lastUsedOn)
  partes.push(usado ? `used ${usado}` : 'never used')

  if (r.expiryTtl != null) {
    partes.push(r.expiryTtl > 0 ? `expires in ${r.expiryTtlString ?? r.expiryTtl}` : 'no expiry')
  }

  return partes
}

/*
Todo lo que no pinta ninguna de las funciones de arriba. Es la red que garantiza
que ningún campo del JSON se cae: se parte de las claves reales del registro y
se descuentan las que ya tienen su sitio.
*/
const YA_PINTADOS = new Set([
  'name',
  'nameIdn',
  'type',
  'ttl',
  'ttlString',
  'rData',
  'dnssecStatus',
  'dnssecRecords',
  'glueRecords',
  'responseMetadata',
  'nameServerMetadata',
  'lastUsedOn',
  'lastModified',
  'expiryTtl',
  'expiryTtlString',
  'disabled',
])

export function extras(r: RegistroDns): Entrada[] {
  const resto: Record<string, unknown> = {}
  for (const clave of Object.keys(r)) {
    if (!YA_PINTADOS.has(clave)) resto[clave] = r[clave]
  }

  const salida = filas(resto)

  // La salud del servidor de nombres es un objeto: se reparte campo a campo
  // para que se lea, en vez de caer como un JSON dentro de una celda.
  if (r.nameServerMetadata) {
    salida.push(...filas(r.nameServerMetadata as unknown as Record<string, unknown>))
  }

  return salida
}
