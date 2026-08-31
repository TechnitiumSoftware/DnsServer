/*
The dropdowns of the two DNSSEC forms (signing a zone and adding a key). **The
label and the value do NOT match**: you see "SHA256 (default)" and `SHA256`
travels, you see "Ed25519 (default)" and `ED25519` travels in uppercase. Copying
the label as the value would break the request without it showing on screen.
*/

export const ALGORITMOS = [
  { valor: 'RSA', etiqueta: 'RSA' },
  { valor: 'ECDSA', etiqueta: 'ECDSA (recommended)' },
  { valor: 'EDDSA', etiqueta: 'EdDSA' },
]

export const HASHES_RSA = [
  { valor: 'MD5', etiqueta: 'MD5 (obsolete)' },
  { valor: 'SHA1', etiqueta: 'SHA1 (obsolete)' },
  { valor: 'SHA256', etiqueta: 'SHA256 (default)' },
  { valor: 'SHA512', etiqueta: 'SHA512' },
]

export const CURVAS_ECDSA = [
  { valor: 'P256', etiqueta: 'P256 (default)' },
  { valor: 'P384', etiqueta: 'P384' },
]

export const CURVAS_EDDSA = [
  { valor: 'ED25519', etiqueta: 'Ed25519 (default)' },
  { valor: 'ED448', etiqueta: 'Ed448' },
]

export const TAMANOS_RSA = ['1024', '1280', '1536', '2048', '3072', '4096']

export const TIPOS_CLAVE = [
  { valor: 'KeySigningKey', etiqueta: 'Key Signing Key (KSK)' },
  { valor: 'ZoneSigningKey', etiqueta: 'Zone Signing Key (ZSK)' },
]

export const PRUEBAS_NX = [
  { valor: 'NSEC', etiqueta: 'Next Secure (NSEC) (recommended)' },
  { valor: 'NSEC3', etiqueta: 'Next Secure 3 (NSEC3)' },
]

export const GENERACIONES = [
  { valor: 'Automatic', etiqueta: 'Automatic Private Key Generation (default)' },
  { valor: 'UseSpecified', etiqueta: 'Use Specified Private Key' },
]

/** Each algorithm's default curve, exactly as `showSignZoneModal` leaves it. */
export function curvaPorDefecto(algoritmo: string): string {
  return algoritmo === 'EDDSA' ? 'ED25519' : 'P256'
}
