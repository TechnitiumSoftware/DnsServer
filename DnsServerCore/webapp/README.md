# webapp — la consola de administración

Fuentes de la interfaz de administración de Technitium DNS Server. Compila a
`../www/`, que es el directorio que el servidor sirve como ficheros estáticos
(`DnsWebService.cs:1832`).

## Construir

```bash
npm install
npm run build        # emite en ../www/
npm run dev          # servidor de desarrollo de Vite
npm run build:check  # emite en dist-check/ sin tocar ../www/
```

Stack: React 19.2, TypeScript 6.0 y Vite 8.2, con `@vitejs/plugin-react` 6.1.
Se usa **npm**, no pnpm ni yarn, para que construir esto no requiera instalar
nada más que Node.

**El build de `www/` va commiteado al repositorio.** Así el servidor .NET no
necesita ningún toolchain de Node para arrancar: quien instale el binario o
compile la solución obtiene la consola ya construida, igual que antes.
`DnsServerCore.csproj` la recoge con el patrón `www\**\*`, porque los nombres
del bundle llevan hash y no se pueden enumerar fichero a fichero.

## Restricciones que impone el servidor

Estas no son preferencias: si se incumplen, la consola rompe en producción
aunque funcione en desarrollo.

- **`base: './'`.** El servidor honra `X-Forwarded-Prefix` y monta un `PathBase`
  (`DnsWebService.cs:1943-1945`). Con rutas absolutas la consola funciona en
  local y da 404 tras un reverse proxy con prefijo. Lo comprueba
  `dev/check-prefijo.sh`.
- **Un solo documento.** El único `MapFallback` del servidor es `/api/{*path}`
  (`DnsWebService.cs:2263`): cualquier ruta profunda daría 404. La navegación va
  por estado interno, nunca por History API.
- **Content-Security-Policy** (`DnsWebService.cs:1969-1975`):
  `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:`. No hay `font-src`,
  así que **las fuentes tienen que ser ficheros bajo `www/`**: una fuente
  embebida como `data:` URI hereda `default-src 'self'` y no carga. Tampoco hay
  CDN posible.
- **`public/` guarda los activos heredados** que `www/` tenía y que el servidor
  o la consola siguen necesitando: `favicon.ico`, `robots.txt`, `img/`
  (incluido `oidc.png`, que usa el login) y `json/*-builtin.json`. El build los
  vuelve a emitir.

## Aviso: el build borra los `*-custom.json` del administrador

La consola lee tres ficheros opcionales que **no** están en el repositorio
porque los crea el administrador a mano en `www/json/`:
`quick-block-lists-custom.json`, `quick-forwarders-list-custom.json` y
`dnsclient-server-list-custom.json`. Cuando falta el `-custom`, se usa el
`-builtin` correspondiente. Está documentado en `www/json/readme.txt`.

**`npm run build` vacía `www/` antes de escribir**, así que cualquier
`*-custom.json` que hubiera allí se pierde. Desplegando sobre una instalación
existente hay que copiarlos fuera antes y devolverlos después. En las instancias
desechables de `dev/` no existen, así que allí da igual.

Esto vivía en un fichero dentro de `public/json/`, o sea que se enviaba a todos
los usuarios; es un aviso para quien construye, no para quien instala.

## Construir la solución completa

`DnsServerCore` referencia por `HintPath` las DLL de
[TechnitiumLibrary](https://github.com/TechnitiumSoftware/TechnitiumLibrary),
que hay que clonar **como carpeta hermana** de este repo y construir primero.
Ver `build.md` en la raíz. Resumen para Linux:

```bash
dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release
dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release
```

`TechnitiumLibrary.Net.Firewall` no compila en Linux (usa una referencia COM de
Windows) y no hace falta: solo lo usa `DnsServerWindowsService`.

## Verificar

`../../dev/` levanta dos instancias en Docker: `dev` con este build y `ref` con
la consola original intacta. Ver `dev/README.md`.
