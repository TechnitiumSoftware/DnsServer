/*
What an open zone's header offers, by type and by DNSSEC state. A replica of the
nine `switch` of `showEditZone` (zone.js:3210-3440).

It is pulled out here because they are nine lists of types that half overlap and
none of which follows from another: there are types that export but do not
import, types that convert but do not clone, and a signed Secondary that shows
the DNSSEC menu but with only "hide records" inside.
*/

export interface CabeceraDeZona {
  anadirRegistro: boolean
  resync: boolean
  importar: boolean
  exportar: boolean
  convertir: boolean
  clonar: boolean
  options: boolean
  permissions: boolean
  /** The whole DNSSEC menu. */
  dnssec: boolean
  firmar: boolean
  desfirmar: boolean
  verDs: boolean
  propiedades: boolean
  /** "Hide / Show DNSSEC Records": it only exists if the zone is signed. */
  alternarRegistrosDnssec: boolean
}

const SECUNDARIAS = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog']
const CONOCIDOS = [...SECUNDARIAS, 'Primary', 'Stub', 'Forwarder', 'Catalog']

/** A Catalog or a Forwarder does not bring the field: they cannot be signed. */
export function isSigned(dnssecStatus: string | undefined): boolean {
  return dnssecStatus === 'SignedWithNSEC' || dnssecStatus === 'SignedWithNSEC3'
}

export function cabeceraDeZona(type: string, dnssecStatus: string | undefined): CabeceraDeZona {
  const signed = isSigned(dnssecStatus)

  const base: CabeceraDeZona = {
    // Only Primary and Forwarder allow adding records by hand.
    anadirRegistro: type === 'Primary' || type === 'Forwarder',
    resync: [...SECUNDARIAS, 'Stub'].includes(type),
    importar: type === 'Primary' || type === 'Forwarder',
    exportar: ['Primary', 'Forwarder', ...SECUNDARIAS, 'Catalog'].includes(type),
    convertir: ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog'].includes(type),
    clonar: type === 'Primary' || type === 'Forwarder',
    options: CONOCIDOS.includes(type),
    permissions: CONOCIDOS.includes(type),
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
      // Sign only if it is NOT; the rest, only if it is.
      firmar: !signed,
      desfirmar: signed,
      verDs: signed,
      propiedades: signed,
      alternarRegistrosDnssec: signed,
    }
  }

  // A signed secondary shows the menu, but INSIDE it can only hide the DNSSEC
  // records: it does not sign, does not unsign and does not see the DS, because
  // the zone is not its own. Unsigned, the menu does not appear at all.
  if (type === 'Secondary' && signed) {
    return { ...base, dnssec: true, alternarRegistrosDnssec: true }
  }

  return base
}

/**
 * Which record types the "Add Record" dropdown offers, which **changes with the
 * zone type and with the DNSSEC state** (zone.js:3213-3250):
 *
 *   · `FWD` only on conditional forwarder zones.
 *   · `DS`, `SSHFP` and `TLSA` only on a SIGNED Primary.
 *   · `ANAME` and `APP` disappear in exactly that case.
 */
export function tiposOcultosAlAnadir(tipoZona: string, dnssecStatus: string | undefined): string[] {
  if (tipoZona === 'Forwarder') return ['DS', 'SSHFP', 'TLSA']

  if (tipoZona === 'Primary') {
    return isSigned(dnssecStatus) ? ['FWD', 'ANAME', 'APP'] : ['FWD', 'DS', 'SSHFP', 'TLSA']
  }

  return []
}

/** The `localStorage` key where upstream stores whether it hides the DNSSEC. */
export const CLAVE_OCULTAR_DNSSEC = 'zoneHideDnssecRecords'

export function leerOcultarDnssec(): boolean {
  try {
    return localStorage.getItem(CLAVE_OCULTAR_DNSSEC) === 'true'
  } catch {
    return false
  }
}

export function guardarOcultarDnssec(value: boolean): void {
  try {
    localStorage.setItem(CLAVE_OCULTAR_DNSSEC, String(value))
  } catch {
    /* Without localStorage the preference does not persist; the screen lives on. */
  }
}
