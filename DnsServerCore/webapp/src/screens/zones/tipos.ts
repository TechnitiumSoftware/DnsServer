export type { Notice } from '../../lib/aviso'

/**
 * An upstream `confirm()` turned into a dialog. The text may carry newlines (the
 * `\n\n` of the bulk delete and of the resync).
 */
export interface Confirmation {
  titulo: string
  text: string
  etiqueta: string
  peligro?: boolean
  action: () => Promise<void>
}
