import { describe, expect, it } from 'vitest'
import { avisoDeFallo } from './aviso'

/*
La traducción de un fallo de la API a un aviso estaba escrita treinta y seis
veces, con tres reservas distintas para cuando el servidor no manda mensaje:
«Unknown error.» en Administration, cadena vacía en DHCP y en Apps, y NADA en
las otras treinta —o sea, un recuadro rojo con su título y el cuerpo en blanco—.
`message` es opcional en `ApiOutcome`, así que las tres eran alcanzables.
*/
describe('avisoDeFallo', () => {
  it('usa el mensaje del servidor cuando lo hay', () => {
    expect(avisoDeFallo({ kind: 'error', message: 'Zone not found.' })).toEqual({
      type: 'danger',
      title: 'Error!',
      text: 'Zone not found.',
    })
  })

  it('un error sin mensaje NO deja el aviso en blanco', () => {
    expect(avisoDeFallo({ kind: 'error' }).text).toBe('Unknown error.')
  })

  it('el token caducado dice lo mismo en toda la consola', () => {
    expect(avisoDeFallo({ kind: 'invalid-token' }).text).toBe('Invalid token or session expired.')
  })
})
