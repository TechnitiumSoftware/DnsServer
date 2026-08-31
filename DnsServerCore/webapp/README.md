# webapp — the administration console

Sources of the Technitium DNS Server administration interface. It builds into
`../www/`, which is the directory the server serves as static files
(`DnsWebService.cs:1832`).

## Building

```bash
npm install
npm run build        # emits into ../www/
npm run dev          # Vite development server
npm run build:check  # emits into dist-check/ without touching ../www/
```

Stack: React 19.2, TypeScript 6.0 and Vite 8.2, with `@vitejs/plugin-react` 6.1.
**npm** is used, not pnpm or yarn, so that building this needs nothing installed
beyond Node.

**The `www/` build is committed to the repository.** That way the .NET server
needs no Node toolchain to start: whoever installs the binary or builds the
solution gets the console already built, exactly as before.
`DnsServerCore.csproj` picks it up with the `www\**\*` pattern, because the
bundle names carry a hash and cannot be listed file by file.

## Constraints the server imposes

These are not preferences: break them and the console fails in production even
though it works in development.

- **`base: './'`.** The server honours `X-Forwarded-Prefix` and mounts a
  `PathBase` (`DnsWebService.cs:1943-1945`). With absolute paths the console
  works locally and 404s behind a reverse proxy with a prefix.
  `dev/check-prefix.sh` checks it.
- **Real routes, one folder per route.** The server's only `MapFallback` is
  `/api/{*path}` (`DnsWebService.cs:2263`), so a deep route with no file on disk
  would 404. The build emits one folder with its own `index.html` for each of
  the console's 32 routes, so the URL is real —no `#/`— and F5 brings you back
  where you were, without touching a line of C#. See `vite.config.ts`.
- **Content-Security-Policy** (`DnsWebService.cs:1969-1975`):
  `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:`. There is no
  `font-src`, so **the fonts have to be files under `www/`**: a font embedded as
  a `data:` URI inherits `default-src 'self'` and does not load. No CDN is
  possible either.
- **`public/` holds the inherited assets** that `www/` had and that the server
  or the console still need: `favicon.ico`, `robots.txt`, `img/` (including
  `oidc.png`, which the login uses) and `json/*-builtin.json`. The build emits
  them again.

## Warning: the build deletes the administrator's `*-custom.json`

The console reads three optional files that are **not** in the repository
because the administrator creates them by hand in `www/json/`:
`quick-block-lists-custom.json`, `quick-forwarders-list-custom.json` and
`dnsclient-server-list-custom.json`. When the `-custom` one is missing, the
matching `-builtin` is used. It is documented in `www/json/readme.txt`.

**`npm run build` empties `www/` before writing**, so any `*-custom.json` that
was there is lost. When deploying over an existing install they have to be
copied out first and put back afterwards. On the disposable instances in `dev/`
they do not exist, so it makes no difference there.

This used to live in a file inside `public/json/`, which meant it was shipped to
every user; it is a warning for whoever builds, not for whoever installs.

## Building the whole solution

`DnsServerCore` references by `HintPath` the DLLs of
[TechnitiumLibrary](https://github.com/TechnitiumSoftware/TechnitiumLibrary),
which has to be cloned **as a sibling folder** of this repo and built first. See
`build.md` at the root. Summary for Linux:

```bash
dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release
dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release
```

`TechnitiumLibrary.Net.Firewall` does not build on Linux (it uses a Windows COM
reference) and is not needed: only `DnsServerWindowsService` uses it.

## Verifying

`../../dev/` brings up two instances in Docker: `dev` with this build and `ref`
with the original console untouched. See `dev/README.md`.

Read [CONVENTIONS.md](CONVENTIONS.md) before touching anything: it is where the
rule that governs the whole project lives —design only, zero functionality— and
the list of upstream behaviours discovered along the way.
