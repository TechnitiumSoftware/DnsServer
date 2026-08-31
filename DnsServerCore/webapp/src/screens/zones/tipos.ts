export type { Notice } from '../../lib/aviso'

/**
 * An upstream `confirm()` turned into a dialog. The text may carry newlines (the
 * `\n\n` of the bulk delete and of the resync).
 */
export interface Confirmation {
  title: string
  text: string
  label: string
  danger?: boolean
  action: () => Promise<void>
}
