import type { AlertType } from '../../ui/Alert'

/** Un aviso de `showAlert`: tipo, título en negrita y texto. Los tres son
 *  literales de upstream y no se componen con plantillas. */
export interface Aviso {
  type: AlertType
  title: string
  text: string
}

/** El aviso de un fallo de la API, igual en las dos pantallas de esta fase. */
export function errorAviso(outcome: { kind: string; message?: string }): Aviso {
  return {
    type: 'danger',
    title: 'Error!',
    text: outcome.kind === 'error' ? (outcome.message ?? '') : 'Invalid token or session expired.',
  }
}
