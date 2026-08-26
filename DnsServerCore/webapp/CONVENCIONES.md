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
- **No todos los endpoints devuelven JSON.** `logs/download` responde
  `text/plain` con el fichero cuando va bien y `application/json` con la
  envoltura de siempre cuando falla. Por `apiRequest` no puede ir: haría
  `res.json()` y convertiría cualquier log en un fallo de red. Upstream lo pide
  con `isTextResponse` y, si lo que llega trae `status`, lo pinta **formateado
  dentro del mismo visor**, como si fuera el contenido del fichero
  (logs.js:170-172). El error no sale como aviso.
- **Dos endpoints de la misma familia pueden no llamar igual al mismo dato**:
  el fichero de log se pide con `fileName` en `logs/download` y con `log` en
  `logs/delete`. Y `logs/list` devuelve el nombre **sin extensión**, que es el
  que hay que mandar en los dos.
- **Confirmar o no confirmar no es simétrico.** En DHCP, deshabilitar un scope
  y borrarlo preguntan; **habilitarlo no pregunta nada** (dhcp.js:583 vs 615).
  Sólo el camino que corta el servicio pregunta.
- **`dhcp/scopes/set` es una actualización PARCIAL**: cada campo se aplica sólo
  si viene en la petición (`WebServiceDhcpApi.cs:390-650`), así que un cuerpo
  con sólo `name` y `newName` renombra sin tocar nada más —comprobado contra
  una instancia v15.4—. Upstream manda siempre los 36. Y **un scope creado con
  este endpoint nace habilitado**, aunque no se le diga nada.
- **`dhcp/scopes/get` OMITE quince claves opcionales** en vez de mandarlas
  `null`: `domainName`, `domainSearchList`, `serverAddress`, `serverHostName`,
  `bootFileName`, `routerAddress`, `dnsServers`, `winsServers`, `ntpServers`,
  `ntpServerDomainNames`, `staticRoutes`, `vendorInfo`, `capwapAcIpAddresses`,
  `tftpServerAddresses`, `genericOptions` y `exclusions`. `reservedLeases` es
  la excepción: se escribe siempre, aunque sea `[]`. Igual `interfaceAddress`
  en `scopes/list`.
- **Un campo se puede omitir a propósito al guardar**: con «Use This DNS
  Server» marcado, upstream **no manda `dnsServers`** (dhcp.js:565). El
  servidor conserva los guardados y `scopes/get` los sigue devolviendo, así que
  la lista que se ve en pantalla no es la que se acaba de mandar.
- **«Borrar algo que no existe responde `ok`» tiene excepciones.**
  `dhcp/scopes/delete` sobre un scope inexistente responde `ok`, pero
  `dhcp/leases/remove` sobre una concesión inexistente responde **error**
  (`No lease was found for client identifier: …`).
- **Dos avisos que parecen el mismo y no lo son.** En Query Logs, el de «falta
  el app» termina en «…from the Apps section.» cuando lo lanza «Query» y **no**
  cuando lo lanza «Export» (logs.js:391 vs 614). Copiar uno en los dos sitios
  cambia un texto.
- **La última página se pide con `pageNumber=-1`**: el servidor la resuelve.
  Es lo que hace el enlace «Last» de Query Logs (logs.js:589), verificado
  contra la instancia de referencia.
- **El rompe-cachés `ts` sólo va en dos de las seis descargas**: copia de
  ajustes (main.js:3100) y `logs/download` (logs.js:196). `logs/export`,
  `zones/export`, `allowed/export` y `blocked/export` **no lo llevan**. El
  servidor lo ignora, pero la URL que se abre no es la misma.
- **Un filtro del formulario puede vivir en `localStorage`**: «Logs Per Page»
  se guarda con la clave `optQueryLogsEntriesPerPage` y se relee en cada reset
  (logs.js:23-26 y 63-65). Ojo: el valor por defecto del formulario es **10** y
  el del servidor es **25** (`WebServiceLogsApi.cs:162`); manda el del
  formulario porque upstream siempre envía el parámetro.
- **`serializeTableData` decodifica DOS veces.** Aplica `htmlDecode` a un valor
  que el navegador ya había decodificado al parsear el HTML, así que escribir
  `&amp;` en una celda manda `&`. En React no hay HTML intermedio: replicarlo
  exigiría introducir el fallo a mano, y no se hace.
- **Un `set` puede devolver menos que su `get`, y hay que conservar lo que
  falta.** `admin/sso/set` NO trae `localGroups`: `WriteSsoConfig` sólo los
  escribe con `includeGroups` y el `set` lo llama con `false`
  (WebServiceAuthApi.cs:1790). Upstream sobrevive porque los guardó en una
  variable global al hacer el `get`. Recargar el formulario con la respuesta del
  guardado sin conservarlos deja los desplegables del mapa de grupos vacíos.
- **Un secreto puede volver ENMASCARADO y hay que reenviarlo así.**
  `admin/sso/get` devuelve `ssoClientSecret: "************"` en cuanto hay uno
  guardado, y `SetSsoConfig` ignora ese valor exacto (WebServiceAuthApi.cs:1738).
  Es lo que permite guardar el formulario sin volver a teclear el secreto:
  limpiar el campo «porque parece un relleno» borraría el secreto de verdad.
- **La misma acción puede mandar parámetros distintos según desde dónde se
  lance.** `admin/sessions/delete` viaja SIEMPRE con `node` desde la pestaña
  Sessions (el nodo primario si la sesión es un token de API, el nodo elegido en
  cualquier otro caso) y **sin `node` en absoluto** desde el modal de detalles
  del usuario salvo que sea un token de API (auth.js:1050 vs 1382).
- **Una casilla puede cambiar el ENDPOINT, no un parámetro.** «Force Remove
  Node» del cluster elige entre `primary/deleteSecondary` y
  `primary/removeSecondary`; «Force Leave» y «Force Delete» del mismo bloque sí
  son parámetros. No se pueden uniformar.
- **Borrar algo que no existe NO siempre responde `ok`.**
  `admin/sessions/delete` con un token parcial inventado responde `error` con
  «No such active session was found for partial token: …». Comprobado en vivo
  contra una v15.4; es la excepción a la regla anotada más arriba.
- **La lista de grupos depende del endpoint que la sirva.**
  `admin/permissions/get?includeUsersAndGroups=true` incluye `Everyone` y
  `admin/groups/list` no; `admin/sso/get?includeGroups=true` lo excluye a
  propósito (WebServiceAuthApi.cs:383). Tres listas de grupos, tres contenidos.
- **Dos endpoints hermanos pueden devolver formas distintas del mismo objeto.**
  `admin/groups/create` responde `{name, description}` y `admin/groups/set`
  responde además `members`. Igual con el usuario: `users/get` trae `groups`
  (todos los del servidor), `users/set` no lo trae aunque sí traiga
  `memberOfGroups` y `sessions`, y `users/list` y `users/create` no traen
  ninguno de los tres. Comprobado en vivo.
- **Media respuesta desaparece cuando el cluster no está inicializado.**
  `admin/cluster/state` en un servidor suelto son TRES campos: `version`,
  `dnsServerDomain` y `clusterInitialized`. `clusterDomain`, los cuatro
  intervalos y `clusterNodes` sólo existen con cluster
  (WebServiceClusterApi.cs:60-75). Y dentro de un nodo, `upSince`, `lastSeen` y
  `configLastSynced` se **omiten** cuando valen `default`, no llegan como
  `null`.
- **«Quick Add» del cluster compara por SUBCADENA.** `cluster.js:30` usa
  `existingList.indexOf(ip) < 0`, así que con `10.0.0.10` ya en la lista la IP
  `10.0.0.1` no se añade nunca. Es un fallo suyo y se replica: se copia lo que
  el código hace, no lo que parece querer hacer.
- **Un aviso de éxito se borra solo a los 5 segundos.** `showAlert`
  (common.js:212) programa un `hideAlert` para los avisos `success` y sólo para
  ésos. La consola nueva no lo replica en ninguna fase; queda anotado por si
  algún día se quiere igualar.
- **Una sección entera puede no filtrar NADA por permiso.** Dentro de
  Administration, upstream comprueba `Administration.canView` para enseñar o
  esconder la sección (main.js:165 y 240) y a partir de ahí muestra todos los
  botones, dejando que el servidor rechace. Añadir gating de cliente ahí sería
  añadir comportamiento, no protegerlo.
- **Permisos asimétricos, el caso concreto de Administration**:
  `permissions/set` y `sso/set` piden `Administration.canDelete`, no
  `canModify` (WebServiceAuthApi.cs:1533 y 1692). En el cluster, casi todo pide
  `canDelete` —incluidos `init`, `initJoin` y `promote`— pero `setOptions`,
  `resync`, `updatePrimary` y `updateIpAddress` piden `canModify`.

- **`zones/list` OMITE `dnssecStatus` y `hasDnssecPrivateKeys` en las zonas
  Catalog y Forwarder**, y la Catalog omite además `catalog`. Son tipos que no
  pueden firmarse, así que el servidor ni escribe los campos. Declararlos
  obligatorios miente sobre media lista y en TypeScript se nota tarde.
- **La misma tabla llama distinto a la misma columna.** En
  `zones/permissions/get`, un permiso de usuario trae `username` y uno de grupo
  trae `name`. Tratarlas como la misma forma deja media tabla en blanco.
- **`records/delete` no tiene rama para CNAME, DNAME, SOA ni APP**: los cuatro
  caen al `default`, que sólo manda `rdata` si existe — y no existe para
  ninguno. El servidor recibe zone+domain+type y nada más. Y **borrar un NS no
  manda `glue`, pero deshabilitarlo sí**: misma pareja de acciones, distinto
  conjunto de parámetros.
- **Deshabilitar un registro lee el TTL de expiración DEL MODAL, no de la fila**
  (`updateRecordState`, zone.js:6236). Si el modal no se ha abierto nunca, manda
  la cadena vacía; si se abrió, manda lo que quedó dentro. Es un fallo de
  upstream: se replica, y por eso la pantalla de registros arrastra ese valor.
- **Un filtro de registros que empieza por `*` busca el comodín literal**, no
  lista todo: tras convertir el glob a regex, `showEditZonePage` reescribe
  `.*\.` inicial a `\*\.`. Sirve para encontrar el registro `*.zona`, que en
  DNS se llama así de verdad. Parece un error y no lo es.
- **El filtro de nombre sin comodín es EXACTO**, no «contiene»: escribir `www`
  no encuentra `www.sub`. Y pasa a minúsculas lo escrito pero **no** el nombre
  de la zona.
- **`zones/create` es POST con los parámetros en la QUERY**: el cuerpo se
  reserva para el fichero de zona opcional (`fileImportZone`). Sin fichero,
  upstream manda un POST sin cuerpo ninguno.
- **`zones/import` tiene DOS formas de mandar el fichero**: subiéndolo va como
  multipart y pegándolo en el textarea va como **texto plano crudo** con
  `Content-Type: text/plain`. El servidor distingue por ese tipo.
- **El borrado en bloque de zonas usa el MISMO endpoint** con el parámetro en
  plural (`zones=`, separadas por coma) y devuelve `deleted` y `failed`. Cuando
  alguna falla, el aviso NO es un error: es un `warning` que cuenta cuántas.
- **La ventana de paginación se desplaza hacia atrás al llegar al final**: en la
  última página se ven las diez últimas, no una sola. Y la última se pide con
  `pageNumber=-1`: la resuelve el servidor.
- **En las opciones de zona, seis listas vacías viajan como la cadena `"false"`
  y dos NO**: `primaryNameServerAddresses` y `queryAccessNetworkACL` viajan
  vacías tal cual. No es simetría; es lo que hace `saveZoneOptions`.
- **Una zona miembro de un catálogo hereda sus opciones**, y eso gobierna la
  interfaz entera de `modalZoneOptions`: si el catálogo no le deja sobrescribir
  una sección, esa pestaña DESAPARECE; si se la deja, aparece editable; y si
  además la administra un catálogo secundario, aparece de sólo lectura.
- **La pestaña que sale abierta en las opciones de zona no es la primera**: en
  una Catalog es «Query Access», y en una Primary depende de si hay catálogos
  disponibles.
- **`convertZone` sólo ofrece tres destinos** —Primary, Forwarder y Catalog— y
  cuáles están habilitados depende del origen con una tabla que no se deduce de
  nada: una Primary sólo puede ir a Forwarder.
- **El año hay que rellenarlo a cuatro dígitos.** `0001-01-01T00:00:00` es el
  `default(DateTime)` de .NET y sale en cada registro sin usar; sin rellenar,
  `getFullYear()` da «1-01-01», que no es lo que escribe moment.
- **En «Add Zone», el tipo Catalog no enseña NADA**: no tiene rama en el
  `switch` de visibilidad, así que sólo quedan el nombre y el tipo.
- **«Secondary ROOT Zone» no es un tipo**: es una Secondary con las direcciones
  de los servidores raíz precargadas, `zoneTransferProtocol=Tcp` y
  `validateZone=true`. El tipo que viaja es `Secondary`.
- **Los rótulos y los valores de los desplegables de DNSSEC no coinciden**: se
  ve «SHA256 (default)» y viaja `SHA256`; se ve «Ed25519 (default)» y viaja
  `ED25519` en MAYÚSCULAS.
- **En las propiedades de DNSSEC, `isRetiring` apaga todas las acciones** de una
  clave, y el rollover automático sólo existe para las ZSK.
- **El rompe-cachés `ts` va en DOS de las seis descargas**, no en tres: la copia
  de ajustes (main.js:3100) y la descarga de un log (logs.js:202). Exportar una
  zona, allowed, blocked y `logs/export` no lo llevan.

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
- **La interfaz va en INGLÉS.** La consola es `lang="en"` y el destino es un
  pull request a upstream: cualquier cadena visible en castellano es un bloqueo
  para ese PR. El castellano es sólo para los comentarios del código.
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
