export type { Aviso } from '../../lib/aviso'

/**
 * Un `confirm()` de upstream convertido en diálogo. El texto puede llevar
 * saltos de línea (los de `\n\n` del borrado en bloque y del resync).
 */
export interface Confirmacion {
  titulo: string
  texto: string
  etiqueta: string
  peligro?: boolean
  accion: () => Promise<void>
}
