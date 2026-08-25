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

## Cierre

Cuando acabes, deja escrito qué endpoints has cubierto y **cualquier
comportamiento de upstream que hayas descubierto y no estuviera anotado**. Eso
último es lo más valioso que puedes aportar.
