/*
Las referencias externas que upstream cita más de una vez.

`ZONEMD` sale en «Add Zone» y en «Zone Options»; `RFC 9276` sale en «Sign Zone»
y en «DNSSEC Properties», dos veces en cada uno. Escritas en un solo sitio
porque un destino repetido a mano es un destino que se actualiza a medias — que
es justo como se perdieron los del panel About.
*/
export const RFC_ZONEMD = 'https://datatracker.ietf.org/doc/rfc8976/'
export const RFC_NSEC3_ITERACIONES = 'https://www.rfc-editor.org/rfc/rfc9276.html#name-iterations'
export const RFC_NSEC3_SAL = 'https://www.rfc-editor.org/rfc/rfc9276.html#name-salt'
export const AYUDA_DNSSEC =
  'https://blog.technitium.com/2022/07/how-to-secure-your-domain-name-with-.html'
