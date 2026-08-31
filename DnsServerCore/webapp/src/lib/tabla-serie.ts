/*
`serializeTableData` (common.js:282), que es como upstream manda al servidor una
tabla editable: Permissions manda dos, y SSO manda los scopes y el mapa de
grupos.

Tres detalles que parecen menores y no lo son:

  · El separador `|` es el MISMO entre columnas y entre filas. El servidor
    reconstruye la tabla por posición (`TryQueryOrFormArray(..., 2, ..., '|')`),
    no por delimitadores distintos.
  · Una casilla se serializa como `"true"` / `"false"`; un campo de texto, tal
    cual. Un campo de texto vacío ABORTA el guardado entero con un aviso, y uno
    que contenga `|` también: son las dos únicas validaciones de la función, y
    son literales de interfaz.
  · Una tabla sin filas produce la cadena VACÍA, no `"false"`. Quien llama
    decide qué hacer con ella: SSO la convierte a `"false"` antes de enviarla
    (auth.js:2265 y 2280) y Permissions la manda vacía.

Vive en `lib/` porque lo usan las CINCO pantallas con tabla editable, y estaba
escrito una vez por pantalla. De las cinco copias salieron cuatro
comportamientos: dos admitían celda opcional, ésta admite casilla booleana y las
dos de Zones no admitían ninguna de las dos cosas. El algoritmo y los dos
literales de aviso son de upstream y son uno solo; lo que sí es de cada pantalla
es cómo LOCALIZA la celda que falla —una fila y una columna aquí, un `id` de
campo en DHCP, una sub-pestaña en Settings—, y por eso el fallo devuelve el
índice y quien llama lo traduce.
*/

export type Celda =
  /** `data-optional` en upstream: la celda que sí puede ir vacía. */
  | { tipo: 'texto'; valor: string; opcional?: boolean }
  | { tipo: 'casilla'; valor: boolean }

export interface FalloTabla {
  title: string
  text: string
  /** Índice de la fila y de la columna del campo que hay que enfocar. */
  fila: number
  columna: number
}

export type ResultadoTabla = { ok: true; valor: string } | { ok: false; fallo: FalloTabla }

export function serializarTabla(filas: readonly (readonly Celda[])[]): ResultadoTabla {
  const salida: string[] = []

  for (let i = 0; i < filas.length; i++) {
    for (let j = 0; j < filas[i].length; j++) {
      const celda = filas[i][j]

      if (celda.tipo === 'casilla') {
        salida.push(celda.valor ? 'true' : 'false')
        continue
      }

      if (celda.valor === '' && celda.opcional !== true) {
        return {
          ok: false,
          fallo: {
            title: 'Missing!',
            text: 'Please enter a valid value in the text field in focus.',
            fila: i,
            columna: j,
          },
        }
      }

      if (celda.valor.includes('|')) {
        return {
          ok: false,
          fallo: {
            title: 'Invalid Character!',
            text: "Please edit the value in the text field in focus to remove '|' character.",
            fila: i,
            columna: j,
          },
        }
      }

      salida.push(celda.valor)
    }
  }

  return { ok: true, valor: salida.join('|') }
}
