# Cómo se construye esta consola

Lee esto entero antes de tocar nada. Es corto y evita los errores que ya se han
cometido.

## La regla que manda sobre todas: solo diseño, cero funcionalidad

Esta consola **sustituye la interfaz de Technitium DNS Server sin cambiar lo que
hace**. Mismos controles, mismos pasos, **mismos textos**, mismo orden de
validación. Cualquier diferencia de comportamiento con la consola de upstream es
un bug, aunque parezca una mejora.

Si te descubres pensando «ya que estoy, esto se puede mejorar»: no. Eso es otro
trabajo.

## Dónde está la referencia

El `www/` viejo **ya no está en el árbol**. Se consulta en la historia:

```bash
git show upstream/master:DnsServerCore/www/js/zone.js
git show upstream/master:DnsServerCore/www/index.html
```

**Los textos de los avisos son contrato.** Sácalos de ahí con `grep -o 'showAlert("[^"]*", "[^"]*", "[^"]*"'` y cópialos literales, en inglés, sin traducir ni reescribir.

## No supongas la forma de las respuestas: compruébala

Hay dos instancias desechables en `dev/`:

- `dev` en <http://127.0.0.1:5380> — sirve nuestro build
- `ref` en <http://127.0.0.1:5381> — la consola de upstream, intacta

Usuario `admin`, contraseña `technitium-ui-dev`. Levanta con `docker compose up -d`
desde `dev/`.

```bash
T=$(curl -s "http://127.0.0.1:5381/api/user/login?user=admin&pass=technitium-ui-dev&includeInfo=false" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s "http://127.0.0.1:5381/api/zones/list?token=$T" | python3 -m json.tool | head -40
```

Tres supuestos que ya han resultado falsos, para que no los repitas:

1. **No todo viene envuelto en `response`.** `user/login`, `user/session/get` y
   `status` devuelven la carga **plana**. El resto sí la envuelve. Por eso
   `apiRequest` **no desenvuelve nada**: entrega el JSON tal cual.
2. El literal del segundo factor es **`2fa-required`**, no `two-factor-auth-required`.
3. Las estadísticas se vuelcan **por minutos**. Un `dig` recién hecho no aparece
   en el Dashboard hasta el siguiente volcado; no concluyas que algo falla.

## Comportamientos de upstream descubiertos sobre la marcha

Anota aquí lo que encuentres. Lo que ya se sabe:

- **Campos opcionales que parecen obligatorios.** En `apps/list`, los campos
  `updateVersion`, `updateUrl` y `updateAvailable` **sólo existen** si el app
  está en el catálogo de la tienda y hay allí una versión compatible; un app
  instalado desde un zip propio no los trae nunca, y si la consulta al catálogo
  agota su plazo de 5 s la lista llega entera pero sin ellos. Tiparlos como
  obligatorios es un error garantizado. Sospecha de todo campo que sólo hayas
  visto una vez.
- **Un campo de texto puede volver como `null`.** `apps/config/get` devuelve
  `config: null` en cuanto alguien guarda una configuración vacía.
- **Los endpoints de subida son POST-only**: por GET el servidor responde
  **404**, no un error JSON.
- **En las subidas, el nombre del campo del fichero da igual**: el servidor coge
  `Form.Files[0]`. Pero **no fijes `Content-Type` a mano** o el `boundary` se
  pierde y el servidor dice que falta el fichero.
- **Borrar algo que no existe suele responder `ok`**, no error.
- **Hay dos paginaciones distintas.** `zones/list` pagina en el servidor
  (`pageNumber`, `zonesPerPage`) y sus campos de paginación **sólo aparecen si
  mandas `pageNumber`**. En cambio `zones/records/get` **no pagina**: se pide con
  `listZone=true` y se pagina en el cliente.
- **Dónde sale un aviso no es cosmético**: en upstream, los avisos de un modal
  salen dentro del modal y los de una pantalla salen en la pantalla. Respétalo.
- **El servidor puede devolverte un dominio distinto del que pediste.** Al
  navegar el árbol de cache/allowed/blocked, `WebServiceOtherZonesApi.cs`
  **desciende solo** mientras el nodo no tenga registros y tenga exactamente un
  hijo. Pinta siempre `response.domain`, **nunca** el dominio que pediste, o el
  árbol y la tabla se desincronizan.
- **El mismo campo puede tener dos tipos según el endpoint.** En `cache/list` el
  `ttl` es una cadena ya compuesta (`"218 (3m38s)"`); en `allowed/list` y
  `blocked/list` es un número con `ttlString` aparte. Igual con `refresh`,
  `retry`, `expire` y `minimum` de un SOA. Tipar los registros con una sola
  forma es un error garantizado.
- **`0001-01-01T00:00:00` es el `default(DateTime)` de .NET**: significa
  «nunca», no el año 1.
- **Reglas de visibilidad que parecen la misma y no lo son**: el borrado de un
  nodo se ofrece en cache si el nodo no es la raíz, y en allowed/blocked si el
  nodo tiene registros. No las uniformes sin mirar.
- **Un recuento puede no estar donde lo pintas.** `blocked/list` sólo lee las
  zonas bloqueadas a mano; las listas de bloqueo descargadas **sólo** se cuentan
  en `dashboard/stats/get` (`blockListZones`).
- **Ojo con replicar la intención en vez del comportamiento.** En `other-zones.js`
  hay tres `domain.toLowerCase();` **sin asignar el resultado**: no hacen nada.
  Se replica lo que el código hace, no lo que parece querer hacer.
- **`settings/get` OMITE las claves nulas**, no las manda como `null`: campos
  como `temporaryDisableBlockingTill` o `blockListNextUpdatedOn` simplemente no
  aparecen en un servidor recién instalado. Otras sí llegan como `null`
  explícito. Declararlas obligatorias falla contra una instalación nueva.
- **Cuidado con `\r\n` al replicar un textarea de lista.** Upstream monta sus
  textareas con `\r\n`, pero el navegador normaliza a `\n` al leer el valor de
  un `<textarea>` del DOM, y su limpieza sólo sustituye `\n`. En React no hay
  DOM intermedio que normalice: copiar el `\r\n` literal manda
  `forwarders=1.1.1.1%0D,8.8.8.8%0D` al servidor. **Muerde a cualquier pantalla
  con listas en textarea.**
- **Una lista vacía viaja como la cadena `"false"`**, no se omite: sale de
  concatenar un booleano a la query. Con tres excepciones que caen a su valor
  por defecto.
- **Una pantalla con sub-pestañas puede ser UN SOLO formulario.** En Settings,
  «Save» manda los campos de las nueve sub-pestañas estés donde estés.
  Trocearlo por pestaña cambiaría lo que se guarda.
- **Una barra de acciones puede mezclar permisos distintos**: en Settings,
  guardar exige `Settings.canModify`, vaciar caché `Cache.canDelete` y la copia
  de seguridad `Settings.canDelete`.
- **Permisos asimétricos**: algunas acciones piden `Delete` donde esperarías
  `Modify`, y `apps/list` se permite con permiso de lectura sobre Apps, Zones
  **o** Logs. No deduzcas el permiso: míralo.

## Cómo se escribe el código

- **Cliente**: siempre `apiRequest` de `src/api/client.ts`. Rutas **relativas y
  sin barra inicial** (`'zones/list'`), porque el servidor honra
  `X-Forwarded-Prefix`.
- **Un fichero `src/api/<familia>.ts` por familia de endpoints**, con sus tipos.
  Que devuelva datos ya usables, y `null` o lista vacía en caso de fallo: la
  pantalla no debe reventar porque el servidor falle.
- **Primitivas** en `src/ui/`: `Button`, `Alert`, `Field`/`LabeledInput`, `Dialog`.
  No inventes botones ni campos sueltos.
- **Colores siempre por token** (`var(--acc)`, `var(--ink)`…). Ni un `#hex` fuera
  de `src/theme/tokens.css`.
- **Un módulo CSS por componente** (`X.module.css`).
- **Un solo tema, el oscuro.** No hay selector de tema.
- **Nada de `BrowserRouter`**: el único `MapFallback` del servidor es `/api/{*path}`.
- **Sin CDN y sin fuentes en `data:`**: la CSP del servidor no declara `font-src`.
  Las imágenes en `data:` sí valen (`img-src 'self' data:`).

## Pruebas

- `npm test` — vitest. **No ejecutes `npm run build`** si hay otros agentes
  trabajando: escribe en `../www` y os pisaríais.
- Cada pantalla necesita pruebas de: **los textos literales de aviso**, el
  **orden de validación**, qué endpoint se llama y con qué cuerpo, y el
  comportamiento con datos vacíos.
- Consulta por etiqueta (`getByLabelText`), no por clase.
- **No asumas que una llamada es la primera**: búscala.
  `spy.mock.calls.find(c => c[0] === 'zones/list')`.
- Con relojes falsos, `findBy*` no funciona: usa
  `vi.useFakeTimers({ shouldAdvanceTime: true })` y `userEvent.setup({ delay: null })`.

## Desviaciones deliberadas del comportamiento de upstream

La regla es «cero funcionalidad», pero hay tres excepciones **decididas y
anotadas**. Si encuentras una cuarta, no la introduzcas por tu cuenta: repórtala.

1. **Un solo tema, el oscuro** (decisión de Adrián). Desaparece el modal
   «Change Theme» y su entrada de menú. Es la única que *quita* algo.
2. **Settings salta a la sub-pestaña del campo inválido.** Upstream da el foco a
   un input oculto y el usuario no ve nada; con un solo panel montado a la vez,
   sin ese salto el aviso sería imposible de resolver.
3. **La casilla «Enable DNS-over-HTTP/3» se rehabilita sola.** En upstream se
   queda muerta hasta recargar la página porque nada re-evalúa su estado: es un
   bug suyo, y replicarlo exigiría introducir el fallo a propósito.

## Cierre

Cuando acabes, deja escrito qué endpoints has cubierto y **cualquier
comportamiento de upstream que hayas descubierto y no estuviera anotado**. Eso
último es lo más valioso que puedes aportar.
