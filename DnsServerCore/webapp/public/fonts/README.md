# Fuentes de la consola

- **Archivo** (Omnibus-Type) para el texto, variable 300-700 — `OFL-Archivo.txt`
- **IBM Plex Mono** para el dato, pesos 400 y 600 — `OFL-IBMPlex.txt`

Las dos bajo SIL Open Font License 1.1, que permite empaquetarlas y
redistribuirlas con el software. **65 KB en total.**

## Por qué van aquí y no en un CDN

La CSP del servidor es `default-src 'self'` sin `font-src`
(`DnsServerCore/DnsWebService.cs:1969-1974`): cualquier fuente que no salga del
propio origen queda bloqueada. Tienen que viajar dentro de `www/`.

## Por qué estas dos

La consola usaba la fuente del sistema operativo, y ésa es la razón de fondo por
la que se leía correcta pero anónima: la misma letra que cualquier otra cosa, y
distinta en cada máquina.

Se descartaron Inter y Geist a propósito. Las dos son excelentes y las dos están
en todas partes —Inter es la de NetBird, Geist la de Vercel— así que ponerlas
habría sido cambiar una fuente prestada por otra.

**Archivo** es un grotesco ligeramente estrechado, de verticales marcadas: tiene
presencia a tamaño pequeño, que es a lo que se lee una tabla de zonas, y un
carácter de producto técnico que no es el de nadie más.

**Plex Mono** es la mitad de lo que enseña esta consola —dominios, direcciones,
seriales, TTL— y ahí lo que importa es que las cifras no se confundan: cero
barrado, uno con base, ele y uno inconfundibles. En un DNS eso no es un detalle
tipográfico, es leer bien una dirección.

Descargadas del subconjunto `latin` que publica Google Fonts.
