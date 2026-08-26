import { apiRequest, type ApiOutcome } from './client'

/*
Los 15 endpoints de DNSSEC de la familia `zones`: `sign`, `unsign`, `viewDS` y
los 12 de `zones/dnssec/properties/*`. Se separan de zones.ts porque son un
sub-sistema entero con su propio vocabulario (claves, estados, pruebas de
no-existencia) y porque juntos son la mitad de la fase.

Réplica de zone.js:6539-7400.

Tres cosas que son contrato y no preferencia nuestra:

  1. **Todos llevan `node`**, el nodo del clúster al que se dirige la petición
     (`optZonesClusterNode`). Con una sola instancia va vacío, y así lo manda
     upstream: la cadena `&node=` viaja igualmente.

  2. **Los parámetros del algoritmo son excluyentes**: RSA manda `hashAlgorithm`
     y los tamaños de clave; ECDSA y EDDSA mandan `curve`. Upstream construye la
     query con un `switch` y NO manda los del algoritmo no elegido. Mandarlos
     todos sería cambiar la petición.

  3. **`nxProof` sólo añade `iterations` y `saltLength` cuando es NSEC3.** Con
     NSEC no viajan.
*/

export type Algoritmo = 'RSA' | 'ECDSA' | 'EDDSA'
export type NxProof = 'NSEC' | 'NSEC3'
export type TipoClave = 'KeySigningKey' | 'ZoneSigningKey'

/** Estados de una clave privada, en el orden del ciclo de vida de upstream. */
export type EstadoClave = 'Generated' | 'Published' | 'Ready' | 'Active' | 'Retired' | 'Revoked'

export interface ClavePrivada {
  keyTag: number
  keyType: TipoClave
  algorithm: string
  algorithmNumber: number
  state: EstadoClave
  stateChangedOn: string
  /** Sólo llega mientras la clave está `Published`. */
  stateReadyBy?: string
  /** Sólo llega mientras la clave está `Ready`. */
  stateActiveBy?: string
  isRetiring: boolean
  rolloverDays: number
}

export interface PropiedadesDnssec {
  name: string
  type: string
  disabled: boolean
  dnssecStatus: string
  dnsKeyTtl: number
  dnssecPrivateKeys: ClavePrivada[]
  /** Sólo con NSEC3. Con NSEC el servidor los omite, no los manda a cero. */
  nsec3Iterations?: number
  nsec3SaltLength?: number
}

export interface Digest {
  digestType: string
  /** Llega como CADENA, no como número, aunque el nombre diga «Number». */
  digestTypeNumber: string
  digest: string
}

export interface RegistroDs {
  keyTag: number
  dnsKeyState: EstadoClave
  /** Puede no venir: sólo existe mientras la clave espera a estar lista. */
  dnsKeyStateReadyBy?: string
  isRetiring: boolean
  algorithm: string
  algorithmNumber: number
  publicKey: string
  digests: Digest[]
}

export interface InfoDs {
  name: string
  type: string
  disabled: boolean
  dnssecStatus: string
  dsRecords: RegistroDs[]
}

/** Parámetros de generación de claves al firmar. Ver `signPrimaryZone`. */
export interface OpcionesFirma {
  algorithm: Algoritmo
  /** RSA */
  hashAlgorithm?: string
  kskKeySize?: string
  zskKeySize?: string
  /** ECDSA y EDDSA */
  curve?: string
  pemKskPrivateKey?: string
  pemZskPrivateKey?: string
  dnsKeyTtl: string
  zskRolloverDays: string
  nxProof: NxProof
  /** Sólo con NSEC3. */
  iterations?: string
  saltLength?: string
}

/**
 * `zones/dnssec/sign`. El orden y el reparto de parámetros replica
 * `signPrimaryZone` (zone.js:6578): los PEM viajan SIEMPRE, aunque estén vacíos,
 * porque upstream los concatena sin condición.
 */
export function signZone(
  token: string | null,
  zone: string,
  o: OpcionesFirma,
  node = '',
): Promise<ApiOutcome> {
  const body: Record<string, string> = {
    zone,
    algorithm: o.algorithm,
    pemKskPrivateKey: o.pemKskPrivateKey ?? '',
    pemZskPrivateKey: o.pemZskPrivateKey ?? '',
    dnsKeyTtl: o.dnsKeyTtl,
    zskRolloverDays: o.zskRolloverDays,
    nxProof: o.nxProof,
  }

  if (o.nxProof === 'NSEC3') {
    body.iterations = o.iterations ?? '0'
    body.saltLength = o.saltLength ?? '0'
  }

  switch (o.algorithm) {
    case 'RSA':
      body.hashAlgorithm = o.hashAlgorithm ?? 'SHA256'
      body.kskKeySize = o.kskKeySize ?? '2048'
      body.zskKeySize = o.zskKeySize ?? '1280'
      break
    case 'ECDSA':
    case 'EDDSA':
      body.curve = o.curve ?? ''
      break
  }

  body.node = node
  return apiRequest('zones/dnssec/sign', { token, body })
}

/** `zones/dnssec/unsign` (zone.js:6681). */
export function unsignZone(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/unsign', { token, body: { zone, node } })
}

/** `zones/dnssec/viewDS` (zone.js:6734). */
export async function verDs(
  token: string | null,
  zone: string,
  node = '',
): Promise<InfoDs | null> {
  const outcome = await apiRequest<{ response: InfoDs }>('zones/dnssec/viewDS', {
    token,
    body: { zone, node },
  })
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return { ...r, dsRecords: r.dsRecords ?? [] }
}

/** `zones/dnssec/properties/get` (zone.js:6836). */
export async function getPropiedades(
  token: string | null,
  zone: string,
  node = '',
): Promise<PropiedadesDnssec | null> {
  const outcome = await apiRequest<{ response: PropiedadesDnssec }>(
    'zones/dnssec/properties/get',
    { token, body: { zone, node } },
  )
  if (outcome.kind !== 'ok') return null
  const r = outcome.data.response
  return { ...r, dnssecPrivateKeys: r.dnssecPrivateKeys ?? [] }
}

/** Parámetros de `addPrivateKey`. Ver `addDnssecPrivateKey` (zone.js:7191). */
export interface OpcionesClaveNueva {
  keyType: TipoClave
  algorithm: Algoritmo
  pemPrivateKey?: string
  rolloverDays: string
  hashAlgorithm?: string
  keySize?: string
  curve?: string
}

export function addPrivateKey(
  token: string | null,
  zone: string,
  o: OpcionesClaveNueva,
  node = '',
): Promise<ApiOutcome> {
  const body: Record<string, string> = {
    zone,
    keyType: o.keyType,
    algorithm: o.algorithm,
    pemPrivateKey: o.pemPrivateKey ?? '',
    rolloverDays: o.rolloverDays,
  }

  switch (o.algorithm) {
    case 'RSA':
      body.hashAlgorithm = o.hashAlgorithm ?? 'SHA256'
      body.keySize = o.keySize ?? '2048'
      break
    case 'ECDSA':
    case 'EDDSA':
      body.curve = o.curve ?? ''
      break
  }

  body.node = node
  return apiRequest('zones/dnssec/properties/addPrivateKey', { token, body })
}

export function updatePrivateKey(
  token: string | null,
  zone: string,
  keyTag: number,
  rolloverDays: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/updatePrivateKey', {
    token,
    body: { zone, keyTag: String(keyTag), rolloverDays, node },
  })
}

export function deletePrivateKey(
  token: string | null,
  zone: string,
  keyTag: number,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/deletePrivateKey', {
    token,
    body: { zone, keyTag: String(keyTag), node },
  })
}

export function publishAllPrivateKeys(
  token: string | null,
  zone: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/publishAllPrivateKeys', {
    token,
    body: { zone, node },
  })
}

export function activateKskDnsKey(
  token: string | null,
  zone: string,
  keyTag: number,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/activateKskDnsKey', {
    token,
    body: { zone, keyTag: String(keyTag), node },
  })
}

export function rolloverDnsKey(
  token: string | null,
  zone: string,
  keyTag: number,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/rolloverDnsKey', {
    token,
    body: { zone, keyTag: String(keyTag), node },
  })
}

export function retireDnsKey(
  token: string | null,
  zone: string,
  keyTag: number,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/retireDnsKey', {
    token,
    body: { zone, keyTag: String(keyTag), node },
  })
}

export function convertToNSEC(token: string | null, zone: string, node = ''): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/convertToNSEC', { token, body: { zone, node } })
}

export function convertToNSEC3(
  token: string | null,
  zone: string,
  iterations: string,
  saltLength: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/convertToNSEC3', {
    token,
    body: { zone, iterations, saltLength, node },
  })
}

export function updateNSEC3Params(
  token: string | null,
  zone: string,
  iterations: string,
  saltLength: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/updateNSEC3Params', {
    token,
    body: { zone, iterations, saltLength, node },
  })
}

export function updateDnsKeyTtl(
  token: string | null,
  zone: string,
  ttl: string,
  node = '',
): Promise<ApiOutcome> {
  return apiRequest('zones/dnssec/properties/updateDnsKeyTtl', {
    token,
    body: { zone, ttl, node },
  })
}

/*
La decisión de qué endpoint llama el botón «Change» de la prueba de
no-existencia NO es del componente: es una tabla de upstream
(`changeDnssecNxProof`, zone.js:7251) y aquí se replica entera, incluido el caso
en que no se llama a nadie y aun así se pinta el aviso de éxito.

  actual → elegido            qué pasa
  NSEC   → NSEC               nada, pero el aviso de éxito se pinta igual
  NSEC   → NSEC3              convertToNSEC3
  NSEC3  → NSEC3, sin cambios nada, pero el aviso de éxito se pinta igual
  NSEC3  → NSEC3, con cambios updateNSEC3Params
  NSEC3  → NSEC               convertToNSEC
*/
export type PlanNxProof =
  | { accion: 'ninguna' }
  | { accion: 'convertToNSEC' }
  | { accion: 'convertToNSEC3'; iterations: string; saltLength: string }
  | { accion: 'updateNSEC3Params'; iterations: string; saltLength: string }

export function planNxProof(
  actual: NxProof,
  elegido: NxProof,
  actuales: { iterations: string; saltLength: string },
  nuevos: { iterations: string; saltLength: string },
): PlanNxProof {
  if (actual === 'NSEC') {
    if (elegido === 'NSEC') return { accion: 'ninguna' }
    return { accion: 'convertToNSEC3', ...nuevos }
  }

  if (elegido === 'NSEC') return { accion: 'convertToNSEC' }

  if (actuales.iterations === nuevos.iterations && actuales.saltLength === nuevos.saltLength) {
    return { accion: 'ninguna' }
  }
  return { accion: 'updateNSEC3Params', ...nuevos }
}
