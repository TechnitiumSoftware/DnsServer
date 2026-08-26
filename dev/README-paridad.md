# Comprobaciones de paridad

## `check-paridad-acciones.sh` — la que de verdad vale

Ejecuta **la misma acción en las dos instancias** y compara el estado que deja
el servidor, no los bytes de la página. Es la verificación que habilita la
restricción rectora del proyecto: como el comportamiento no cambia, si el cuerpo
que manda la consola nueva difiere en un parámetro, el registro que queda
difiere y aquí sale.

```bash
docker compose up -d
./check-paridad-acciones.sh
```

Cubre catorce acciones: siete altas (incluidas las que tienen trampa —TXT
partido, SVCB con `svcParams` aplanados, CAA con sus valores por defecto—),
tres ediciones (entre ellas deshabilitar un registro, que en upstream es un
`records/update` reenviando el registro entero), tres borrados (incluido el
CNAME, que cae al `default` y no manda ningún parámetro de identidad) y el
`options/set` con las seis listas vacías viajando como la cadena `"false"`.

Normaliza tres cosas antes de comparar, y las tres porque no son paridad:
`lastModified`, el serial del SOA y **el nombre del propio servidor**, que va
metido en el NS y el SOA de cada zona y es distinto en cada contenedor a
propósito.

## `check-paridad.sh` — sólo para los ficheros preservados

Compara el contenido de una ruta entre las dos instancias. Desde la fase 0 la
consola es nuestra, así que **para `/` da `DISTINTOS` y eso es el objetivo del
proyecto**. Sigue sirviendo para lo que el build preserva sin tocar:

```bash
./check-paridad.sh /robots.txt   # IDENTICOS
./check-paridad.sh /favicon.ico  # IDENTICOS
```

## `paridad-login.mjs`

Compara los avisos de la pantalla de login entre la consola
nueva (5380) y la de upstream (5381). Necesita Playwright:

```bash
npm i -D playwright && npx playwright install chromium
node paridad-login.mjs
```

Encontró dos divergencias reales la primera vez que se ejecutó: faltaba el botón
«×» para descartar el aviso —que en upstream existe, así que su ausencia era una
diferencia de comportamiento— y faltaba el espacio entre el título y el texto.
