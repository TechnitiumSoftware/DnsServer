/*
What an open zone's header offers, by type and by DNSSEC state. A replica of the
nine `switch` of `showEditZone` (zone.js:3210-3440).

It is pulled out here because they are nine lists of types that half overlap and
none of which follows from another: there are types that export but do not
import, types that convert but do not clone, and a signed Secondary that shows
the DNSSEC menu but with only "hide records" inside.
*/

export interface ZoneHeader {
  addRecord: boolean
  resync: boolean
  runImport: boolean
  runExport: boolean
  convert: boolean
  clone: boolean
  options: boolean
  permissions: boolean
  /** The whole DNSSEC menu. */
  dnssec: boolean
  sign: boolean
  unsign: boolean
  viewDs: boolean
  properties: boolean
  /** "Hide / Show DNSSEC Records": it only exists if the zone is signed. */
  toggleDnssecRecords: boolean
}

const SECONDARIES = ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog']
const KNOWN = [...SECONDARIES, 'Primary', 'Stub', 'Forwarder', 'Catalog']

/** A Catalog or a Forwarder does not bring the field: they cannot be signed. */
export function isSigned(dnssecStatus: string | undefined): boolean {
  return dnssecStatus === 'SignedWithNSEC' || dnssecStatus === 'SignedWithNSEC3'
}

export function zoneHeader(type: string, dnssecStatus: string | undefined): ZoneHeader {
  const signed = isSigned(dnssecStatus)

  const base: ZoneHeader = {
    // Only Primary and Forwarder allow adding records by hand.
    addRecord: type === 'Primary' || type === 'Forwarder',
    resync: [...SECONDARIES, 'Stub'].includes(type),
    runImport: type === 'Primary' || type === 'Forwarder',
    runExport: ['Primary', 'Forwarder', ...SECONDARIES, 'Catalog'].includes(type),
    convert: ['Primary', 'Secondary', 'SecondaryForwarder', 'Forwarder', 'SecondaryCatalog'].includes(type),
    clone: type === 'Primary' || type === 'Forwarder',
    options: KNOWN.includes(type),
    permissions: KNOWN.includes(type),
    dnssec: false,
    sign: false,
    unsign: false,
    viewDs: false,
    properties: false,
    toggleDnssecRecords: false,
  }

  if (type === 'Primary') {
    return {
      ...base,
      dnssec: true,
      // Sign only if it is NOT; the rest, only if it is.
      sign: !signed,
      unsign: signed,
      viewDs: signed,
      properties: signed,
      toggleDnssecRecords: signed,
    }
  }

  // A signed secondary shows the menu, but INSIDE it can only hide the DNSSEC
  // records: it does not sign, does not unsign and does not see the DS, because
  // the zone is not its own. Unsigned, the menu does not appear at all.
  if (type === 'Secondary' && signed) {
    return { ...base, dnssec: true, toggleDnssecRecords: true }
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
export function typesHiddenWhenAdding(zoneType: string, dnssecStatus: string | undefined): string[] {
  if (zoneType === 'Forwarder') return ['DS', 'SSHFP', 'TLSA']

  if (zoneType === 'Primary') {
    return isSigned(dnssecStatus) ? ['FWD', 'ANAME', 'APP'] : ['FWD', 'DS', 'SSHFP', 'TLSA']
  }

  return []
}

/** The `localStorage` key where upstream stores whether it hides the DNSSEC. */
export const HIDE_DNSSEC_KEY = 'zoneHideDnssecRecords'

export function readHideDnssec(): boolean {
  try {
    return localStorage.getItem(HIDE_DNSSEC_KEY) === 'true'
  } catch {
    return false
  }
}

export function writeHideDnssec(value: boolean): void {
  try {
    localStorage.setItem(HIDE_DNSSEC_KEY, String(value))
  } catch {
    /* Without localStorage the preference does not persist; the screen lives on. */
  }
}
