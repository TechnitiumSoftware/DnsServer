/*
Los desplegables de los dos formularios de DNSSEC (firmar una zona y añadir una
clave). **La etiqueta y el valor NO coinciden**: se ve «SHA256 (default)» y
viaja `SHA256`, se ve «Ed25519 (default)» y viaja `ED25519` en mayúsculas.
Copiar la etiqueta como valor rompería la petición sin que se note en pantalla.
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

/** La curva por defecto de cada algoritmo, tal como la deja `showSignZoneModal`. */
export function curvaPorDefecto(algoritmo: string): string {
  return algoritmo === 'EDDSA' ? 'ED25519' : 'P256'
}
