/*
Qué ofrece la cabecera de una zona abierta, por tipo y por estado DNSSEC.
Réplica de los nueve `switch` de `showEditZone` (zone.js:3210-3440).

Se extrae aquí porque son nueve listas de tipos que se solapan a medias y
ninguna se deduce de otra: hay tipos que exportan pero no importan, tipos que
convierten pero no clonan, y una Secondary firmada que enseña el menú DNSSEC
pero sólo con «ocultar registros» dentro.
*/

export interface CabeceraDeZona {
  anadirRegistro: boolean
  resync: boolean
  importar: boolean
  exportar: boolean
  convertir: boolean
  clonar: boolean
  opciones: boolean
  permisos: boolean
  /** El menú DNSSEC entero. */
  dnssec: boolean
  firmar: boolean
  desfirmar: boolean
  verDs: boolean
  propiedades: boolean
  /** «Hide / Show DNSSEC Records»: sólo existe si la zona está firmada. */
  alternarRegistrosDnssec: boolean
}

const SECUNDARIAS = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog']
const CONOCIDOS = [...SECUNDARIAS, 'Primary', 'Stub', 'Forwarder', 'Catalog']

/** Una Catalog o una Forwarder no traen el campo: no se pueden firmar. */
export function estaFirmada(dnssecStatus: string | undefined): boolean {
  return dnssecStatus === 'SignedWithNSEC' || dnssecStatus === 'SignedWithNSEC3'
}

export function cabeceraDeZona(type: string, dnssecStatus: string | undefined): CabeceraDeZona {
  const firmada = estaFirmada(dnssecStatus)

  const base: CabeceraDeZona = {
    // Sólo Primary y Forwarder permiten añadir registros a mano.
    anadirRegistro: type === 'Primary' || type === 'Forwarder',
    resync: [...SECUNDARIAS, 'Stub'].includes(type),
    importar: type === 'Primary' || type === 'Forwarder',
    exportar: ['Primary', 'Forwarder', ...SECUNDARIAS, 'Catalog'].includes(type),
    convertir: ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog'].includes(type),
    clonar: type === 'Primary' || type === 'Forwarder',
    opciones: CONOCIDOS.includes(type),
    permisos: CONOCIDOS.includes(type),
    dnssec: false,
    firmar: false,
    desfirmar: false,
    verDs: false,
    propiedades: false,
    alternarRegistrosDnssec: false,
  }

  if (type === 'Primary') {
    return {
      ...base,
      dnssec: true,
      // Firmar sólo si NO lo está; el resto, sólo si lo está.
      firmar: !firmada,
      desfirmar: firmada,
      verDs: firmada,
      propiedades: firmada,
      alternarRegistrosDnssec: firmada,
    }
  }

  // Una secundaria firmada enseña el menú, pero DENTRO sólo puede ocultar los
  // registros DNSSEC: no firma, no desfirma y no ve el DS, porque la zona no
  // es suya. Sin firmar, el menú no aparece en absoluto.
  if (type === 'Secondary' && firmada) {
    return { ...base, dnssec: true, alternarRegistrosDnssec: true }
  }

  return base
}

/**
 * Qué tipos de registro ofrece el desplegable de «Add Record», que **cambia
 * con el tipo de zona y con el estado DNSSEC** (zone.js:3213-3250):
 *
 *   · `FWD` sólo en zonas de reenvío condicional.
 *   · `DS`, `SSHFP` y `TLSA` sólo en una Primary FIRMADA.
 *   · `ANAME` y `APP` desaparecen justo en ese caso.
 */
export function tiposOcultosAlAnadir(tipoZona: string, dnssecStatus: string | undefined): string[] {
  if (tipoZona === 'Forwarder') return ['DS', 'SSHFP', 'TLSA']

  if (tipoZona === 'Primary') {
    return estaFirmada(dnssecStatus) ? ['FWD', 'ANAME', 'APP'] : ['FWD', 'DS', 'SSHFP', 'TLSA']
  }

  return []
}

/** Clave de `localStorage` donde upstream guarda si esconde los DNSSEC. */
export const CLAVE_OCULTAR_DNSSEC = 'zoneHideDnssecRecords'

export function leerOcultarDnssec(): boolean {
  try {
    return localStorage.getItem(CLAVE_OCULTAR_DNSSEC) === 'true'
  } catch {
    return false
  }
}

export function guardarOcultarDnssec(valor: boolean): void {
  try {
    localStorage.setItem(CLAVE_OCULTAR_DNSSEC, String(valor))
  } catch {
    /* Sin localStorage la preferencia no persiste; la pantalla sigue viva. */
  }
}
