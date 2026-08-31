import { apiRequest, type ApiOutcome } from './client'

/*
The 15 DNSSEC endpoints of the `zones` family: `sign`, `unsign`, `viewDS` and
the 12 of `zones/dnssec/properties/*`. They are kept apart from zones.ts because
they are a whole sub-system with a vocabulary of their own (keys, states,
proofs of non-existence) and because together they are half the phase.

A replica of zone.js:6539-7400.

Three things that are contract and not our preference:

  1. **They all carry `node`**, the cluster node the request is aimed at
     (`optZonesClusterNode`). With a single instance it goes empty, and that is
     how upstream sends it: the string `&node=` travels all the same.

  2. **The algorithm's parameters are mutually exclusive**: RSA sends
     `hashAlgorithm` and the key sizes; ECDSA and EDDSA send `curve`. Upstream
     builds the query with a `switch` and does NOT send the ones of the algorithm
     that was not chosen. Sending them all would be changing the request.

  3. **`nxProof` only adds `iterations` and `saltLength` when it is NSEC3.** With
     NSEC they do not travel.
*/

export type Algoritmo = 'RSA' | 'ECDSA' | 'EDDSA'
export type NxProof = 'NSEC' | 'NSEC3'
export type TipoClave = 'KeySigningKey' | 'ZoneSigningKey'

/** States of a private key, in the order of upstream's life cycle. */
export type EstadoClave = 'Generated' | 'Published' | 'Ready' | 'Active' | 'Retired' | 'Revoked'

export interface ClavePrivada {
  keyTag: number
  keyType: TipoClave
  algorithm: string
  algorithmNumber: number
  state: EstadoClave
  stateChangedOn: string
  /** Only arrives while the key is `Published`. */
  stateReadyBy?: string
  /** Only arrives while the key is `Ready`. */
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
  /** Only with NSEC3. With NSEC the server omits them, it does not send them as zero. */
  nsec3Iterations?: number
  nsec3SaltLength?: number
}

export interface Digest {
  digestType: string
  /** Arrives as a STRING, not as a number, however much the name says "Number". */
  digestTypeNumber: string
  digest: string
}

export interface RegistroDs {
  keyTag: number
  dnsKeyState: EstadoClave
  /** It may not come: it only exists while the key is waiting to be ready. */
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

/** Key-generation parameters when signing. See `signPrimaryZone`. */
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
  /** Only with NSEC3. */
  iterations?: string
  saltLength?: string
}

/**
 * `zones/dnssec/sign`. The order and the split of parameters replicates
 * `signPrimaryZone` (zone.js:6578): the PEMs ALWAYS travel, even when empty,
 * because upstream concatenates them unconditionally.
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

/** Parameters of `addPrivateKey`. See `addDnssecPrivateKey` (zone.js:7191). */
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
Which endpoint the proof-of-non-existence "Change" button calls is not the
component's decision: it is a table from upstream (`changeDnssecNxProof`,
zone.js:7251) and it is replicated here whole, including the case where nobody is
called and the success alert is drawn all the same.

  current → chosen           what happens
  NSEC    → NSEC             nothing, but the success alert is drawn anyway
  NSEC    → NSEC3            convertToNSEC3
  NSEC3   → NSEC3, unchanged nothing, but the success alert is drawn anyway
  NSEC3   → NSEC3, changed   updateNSEC3Params
  NSEC3   → NSEC             convertToNSEC
*/
export type PlanNxProof =
  | { action: 'ninguna' }
  | { action: 'convertToNSEC' }
  | { action: 'convertToNSEC3'; iterations: string; saltLength: string }
  | { action: 'updateNSEC3Params'; iterations: string; saltLength: string }

export function planNxProof(
  current: NxProof,
  elegido: NxProof,
  actuales: { iterations: string; saltLength: string },
  nuevos: { iterations: string; saltLength: string },
): PlanNxProof {
  if (current === 'NSEC') {
    if (elegido === 'NSEC') return { action: 'ninguna' }
    return { action: 'convertToNSEC3', ...nuevos }
  }

  if (elegido === 'NSEC') return { action: 'convertToNSEC' }

  if (actuales.iterations === nuevos.iterations && actuales.saltLength === nuevos.saltLength) {
    return { action: 'ninguna' }
  }
  return { action: 'updateNSEC3Params', ...nuevos }
}
