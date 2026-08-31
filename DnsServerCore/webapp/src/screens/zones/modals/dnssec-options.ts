/*
The dropdowns of the two DNSSEC forms (signing a zone and adding a key). **The
label and the value do NOT match**: you see "SHA256 (default)" and `SHA256`
travels, you see "Ed25519 (default)" and `ED25519` travels in uppercase. Copying
the label as the value would break the request without it showing on screen.
*/

export const ALGORITHMS = [
  { value: 'RSA', label: 'RSA' },
  { value: 'ECDSA', label: 'ECDSA (recommended)' },
  { value: 'EDDSA', label: 'EdDSA' },
]

export const HASHES_RSA = [
  { value: 'MD5', label: 'MD5 (obsolete)' },
  { value: 'SHA1', label: 'SHA1 (obsolete)' },
  { value: 'SHA256', label: 'SHA256 (default)' },
  { value: 'SHA512', label: 'SHA512' },
]

export const CURVAS_ECDSA = [
  { value: 'P256', label: 'P256 (default)' },
  { value: 'P384', label: 'P384' },
]

export const CURVAS_EDDSA = [
  { value: 'ED25519', label: 'Ed25519 (default)' },
  { value: 'ED448', label: 'Ed448' },
]

export const TAMANOS_RSA = ['1024', '1280', '1536', '2048', '3072', '4096']

export const KEY_TYPES = [
  { value: 'KeySigningKey', label: 'Key Signing Key (KSK)' },
  { value: 'ZoneSigningKey', label: 'Zone Signing Key (ZSK)' },
]

export const PRUEBAS_NX = [
  { value: 'NSEC', label: 'Next Secure (NSEC) (recommended)' },
  { value: 'NSEC3', label: 'Next Secure 3 (NSEC3)' },
]

export const GENERACIONES = [
  { value: 'Automatic', label: 'Automatic Private Key Generation (default)' },
  { value: 'UseSpecified', label: 'Use Specified Private Key' },
]

/** Each algorithm's default curve, exactly as `showSignZoneModal` leaves it. */
export function curvaPorDefecto(algorithm: string): string {
  return algorithm === 'EDDSA' ? 'ED25519' : 'P256'
}
