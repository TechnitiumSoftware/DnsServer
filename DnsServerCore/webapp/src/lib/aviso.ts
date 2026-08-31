import type { AlertType } from '../ui/Alert'

/*
Un `showAlert` de upstream: tipo, título en negrita y texto. Los tres son
literales de upstream y no se componen con plantillas.

Este tipo estaba declarado OCHO veces —en Administration, DHCP, Zones, Listas,
las dos pantallas de Logs, y con otro nombre en Settings y en Apps— con las
mismas tres propiedades.
*/
export interface Aviso {
  type: AlertType
  title: string
  text: string
}

/*
`showAlert("danger", "Error!", …)`: upstream lo saca SIEMPRE que la respuesta no
es `ok`, con el mensaje que manda el servidor.

La traducción estaba escrita treinta y seis veces, y con tres reservas distintas
para cuando el servidor no manda mensaje: «Unknown error.» en Administration,
cadena vacía en DHCP y en Apps, y NADA en las otras treinta —o sea, un recuadro
rojo con su título y el cuerpo en blanco—. `message` es opcional en
`ApiOutcome`, así que las tres eran alcanzables.

Se queda «Unknown error.», que es la única de las tres que dice algo.
*/
export function avisoDeFallo(outcome: { kind: string; message?: string }): Aviso {
  return {
    type: 'danger',
    title: 'Error!',
    text:
      outcome.kind === 'error'
        ? (outcome.message ?? 'Unknown error.')
        : 'Invalid token or session expired.',
  }
}
