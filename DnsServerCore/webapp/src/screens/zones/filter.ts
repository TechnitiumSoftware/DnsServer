import type { ResourceRecord } from '../../api/records'

/*
The records table's filter (`showEditZonePage`, zone.js:3524-3570). It is the
client's, not the server's, because `zones/records/get` brings the whole zone.

Three rules that are not obvious and that are replicated as they are:

  1. **Without a wildcard the comparison is exact**, not "contains". Typing `www`
     does not find `www.sub`: you have to type `www*`.

  2. **`@` means the zone's apex**, and at the root it means the empty name.

  3. **A filter starting with `*` looks for the literal wildcard record.** It is
     the line that most looks like a bug and is not: after converting the glob to
     a regex, if the expression starts with `.*\.` upstream rewrites it to
     `\*\.`, that is, a literal asterisk. It serves to find the `*.zone` record,
     which in DNS really is called that. Without that line, typing `*` would list
     everything; with it, it lists only the wildcard. It is kept.
*/

export interface Filter {
  name: string
  type: string
}

/** Translates the name filter into the domain or the expression to compare against. */
export function compilarFiltroDeNombre(
  filterName: string,
  zone: string,
): { domain: string | null; regex: RegExp | null } {
  if (filterName === '') return { domain: null, regex: null }

  let domain = filterName.toLowerCase()

  if (zone === '.') {
    if (domain === '@') domain = ''
  } else if (domain === '@') {
    domain = zone
  } else {
    domain += `.${zone}`
  }

  if (filterName.indexOf('*') === -1 && filterName.indexOf('?') === -1) {
    return { domain, regex: null }
  }

  let pattern = domain.replace(/\./g, '\\.')
  pattern = pattern.replace(/\*/g, '.*')
  pattern = pattern.replace(/\?/g, '.')

  // See rule 3 of the header: `.*\.` at the start is a literal asterisk.
  if (pattern.startsWith('.*\\.')) pattern = `\\*${pattern.substring(2)}`

  return { domain, regex: new RegExp(`^${pattern}$`) }
}

/**
 * Applies both filters. The type one is exact and uppercased; the name one,
 * whatever `compilarFiltroDeNombre` returns. It needs the zone because without
 * it `@` cannot be resolved.
 */
export function filterBy(records: ResourceRecord[], filter: Filter, zone: string): ResourceRecord[] {
  const { name, type } = filter
  if (name === '' && type === '') return records

  const { domain, regex } = compilarFiltroDeNombre(name, zone)
  const wantedType = type === '' ? null : type.toUpperCase()

  return records.filter((r) => {
    const nombreReg = r.name.toLowerCase()

    if (regex == null) {
      if (domain != null && nombreReg !== domain) return false
    } else if (!regex.test(nombreReg)) {
      return false
    }

    if (wantedType != null && r.type !== wantedType) return false
    return true
  })
}
