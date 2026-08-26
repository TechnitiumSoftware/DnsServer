import type { AlertType } from '../../ui/Alert'

/** Un `showAlert` de upstream: tipo, título en negrita y texto. */
export interface Aviso {
  type: AlertType
  title: string
  text: string
}

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
