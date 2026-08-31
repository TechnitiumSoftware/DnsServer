/*
The dropdowns of the two DNSSEC forms (signing a zone and adding a key). **The
label and the value do NOT match**: you see "SHA256 (default)" and `SHA256`
travels, you see "Ed25519 (default)" and `ED25519` travels in uppercase. Copying
the label as the value would break the request without it showing on screen.
*/

export const ALGORITMOS = [
  { value: 'RSA', etiqueta: 'RSA' },
  { value: 'ECDSA', etiqueta: 'ECDSA (recommended)' },
  { value: 'EDDSA', etiqueta: 'EdDSA' },
]

export const HASHES_RSA = [
  { value: 'MD5', etiqueta: 'MD5 (obsolete)' },
  { value: 'SHA1', etiqueta: 'SHA1 (obsolete)' },
  { value: 'SHA256', etiqueta: 'SHA256 (default)' },
  { value: 'SHA512', etiqueta: 'SHA512' },
]

export const CURVAS_ECDSA = [
  { value: 'P256', etiqueta: 'P256 (default)' },
  { value: 'P384', etiqueta: 'P384' },
]

export const CURVAS_EDDSA = [
  { value: 'ED25519', etiqueta: 'Ed25519 (default)' },
  { value: 'ED448', etiqueta: 'Ed448' },
]

export const TAMANOS_RSA = ['1024', '1280', '1536', '2048', '3072', '4096']

export const TIPOS_CLAVE = [
  { value: 'KeySigningKey', etiqueta: 'Key Signing Key (KSK)' },
  { value: 'ZoneSigningKey', etiqueta: 'Zone Signing Key (ZSK)' },
]

export const PRUEBAS_NX = [
  { value: 'NSEC', etiqueta: 'Next Secure (NSEC) (recommended)' },
  { value: 'NSEC3', etiqueta: 'Next Secure 3 (NSEC3)' },
]

export const GENERACIONES = [
  { value: 'Automatic', etiqueta: 'Automatic Private Key Generation (default)' },
  { value: 'UseSpecified', etiqueta: 'Use Specified Private Key' },
]

/** Each algorithm's default curve, exactly as `showSignZoneModal` leaves it. */
export function curvaPorDefecto(algoritmo: string): string {
  return algoritmo === 'EDDSA' ? 'ED25519' : 'P256'
}
