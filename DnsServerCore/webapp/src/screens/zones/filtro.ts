import type { Registro } from '../../api/registros'

/*
El filtro de la tabla de registros (`showEditZonePage`, zone.js:3524-3570).
Es del cliente, no del servidor, porque `zones/records/get` trae la zona entera.

Tres reglas que no son evidentes y que se replican tal cual:

  1. **Sin comodín, la comparación es exacta**, no «contiene». Escribir `www`
     no encuentra `www.sub`: hay que escribir `www*`.

  2. **`@` significa el ápice de la zona**, y en la raíz significa el nombre
     vacío.

  3. **Un filtro que empieza por `*` busca el registro comodín literal.** Es la
     línea que más parece un error y no lo es: tras convertir el glob a regex,
     si la expresión empieza por `.*\.` upstream la reescribe a `\*\.`, o sea,
     un asterisco literal. Sirve para encontrar el registro `*.zona`, que en DNS
     se llama así de verdad. Sin esa línea, escribir `*` listaría todo; con
     ella, lista sólo el comodín. Se conserva.
*/

export interface Filtro {
  nombre: string
  tipo: string
}

/** Traduce el filtro de nombre al dominio o a la expresión que se comparará. */
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

  // Ver la regla 3 de la cabecera: `.*\.` al principio es un asterisco literal.
  if (patron.startsWith('.*\\.')) patron = `\\*${patron.substring(2)}`

  return { dominio, regex: new RegExp(`^${patron}$`) }
}

/**
 * Aplica los dos filtros. El de tipo es exacto y en mayúsculas; el de nombre,
 * lo que devuelva `compilarFiltroDeNombre`. Necesita la zona porque sin ella no
 * se puede resolver `@`.
 */
export function filtrar(registros: Registro[], filtro: Filtro, zone: string): Registro[] {
  const { nombre, tipo } = filtro
  if (nombre === '' && tipo === '') return registros

  const { dominio, regex } = compilarFiltroDeNombre(nombre, zone)
  const tipoBuscado = tipo === '' ? null : tipo.toUpperCase()

  return registros.filter((r) => {
    const nombreReg = r.name.toLowerCase()

    if (regex == null) {
      if (dominio != null && nombreReg !== dominio) return false
    } else if (!regex.test(nombreReg)) {
      return false
    }

    if (tipoBuscado != null && r.type !== tipoBuscado) return false
    return true
  })
}
