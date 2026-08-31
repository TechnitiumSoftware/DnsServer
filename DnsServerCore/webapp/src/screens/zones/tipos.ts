export type { Aviso } from '../../lib/aviso'

/**
 * An upstream `confirm()` turned into a dialog. The text may carry newlines (the
 * `\n\n` of the bulk delete and of the resync).
 */
export interface Confirmacion {
  titulo: string
  texto: string
  etiqueta: string
  peligro?: boolean
  accion: () => Promise<void>
}
