import type { ResourceRecord } from '../../api/registros'

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
): { dominio: string | null; regex: RegExp | null } {
  if (filterName === '') return { dominio: null, regex: null }

  let dominio = filterName.toLowerCase()

  if (zone === '.') {
    if (dominio === '@') dominio = ''
  } else if (dominio === '@') {
    dominio = zone
  } else {
    dominio += `.${zone}`
  }

  if (filterName.indexOf('*') === -1 && filterName.indexOf('?') === -1) {
    return { dominio, regex: null }
  }

  let patron = dominio.replace(/\./g, '\\.')
  patron = patron.replace(/\*/g, '.*')
  patron = patron.replace(/\?/g, '.')

  // See rule 3 of the header: `.*\.` at the start is a literal asterisk.
  if (patron.startsWith('.*\\.')) patron = `\\*${patron.substring(2)}`

  return { dominio, regex: new RegExp(`^${patron}$`) }
}

/**
 * Applies both filters. The type one is exact and uppercased; the name one,
 * whatever `compilarFiltroDeNombre` returns. It needs the zone because without
 * it `@` cannot be resolved.
 */
export function filterBy(records: ResourceRecord[], filter: Filter, zone: string): ResourceRecord[] {
  const { name, type } = filter
  if (name === '' && type === '') return records

  const { dominio, regex } = compilarFiltroDeNombre(name, zone)
  const wantedType = type === '' ? null : type.toUpperCase()

  return records.filter((r) => {
    const nombreReg = r.name.toLowerCase()

    if (regex == null) {
      if (dominio != null && nombreReg !== dominio) return false
    } else if (!regex.test(nombreReg)) {
      return false
    }

    if (wantedType != null && r.type !== wantedType) return false
    return true
  })
}
