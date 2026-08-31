import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { STATIC_ROUTES } from './src/app/static-routes.js'

/*
One folder with its own `index.html` for each route of the console.

The server serves `www/` with static files and `UseDefaultFiles()`
(DnsWebService.cs:1960): `/settings/logging/` resolves to
`/settings/logging/index.html`, and `/settings/logging` gets a 301 to the
trailing-slash version. With the file in place the URL is real —no `#/`— and F5
brings you back where you were, **without touching a line of C#**.

The asset paths are corrected to the depth of each copy (`../` or `../../`). It
is not cosmetic: `base` is relative on purpose —the server honours
`X-Forwarded-Prefix` by mounting a `PathBase`, and with an absolute base the
console breaks behind a prefixed proxy— so the only way for
`/dns/settings/logging/` to find `/dns/assets/…` is to count the hops.

And each copy carries its route in a `<meta>`, which is what lets the application
know its own root without knowing the prefix: the root is its `pathname` minus
those segments.
*/
function staticRoutes(): Plugin {
  return {
    name: 'static-routes',
    enforce: 'post',
    generateBundle(_opciones, paquete) {
      const indice = paquete['index.html']
      if (indice == null || indice.type !== 'asset') return

      for (const route of STATIC_ROUTES) {
        const saltos = '../'.repeat(route.split('/').length)
        const html = String(indice.source)
          .replace(/(href|src)="\.\//g, `$1="${saltos}`)
          .replace('<head>', `<head>\n    <meta name="route" content="${route}" />`)

        this.emitFile({ type: 'asset', fileName: `${route}/index.html`, source: html })
      }
    },
  }
}

export default defineConfig(({ mode }) => ({
  // The .NET server serves DnsServerCore/www/ as static files
  // (DnsWebService.cs:1832) and honours X-Forwarded-Prefix by mounting a
  // PathBase (DnsWebService.cs:1943-1945). That is why base has to be relative:
  // with an absolute base the console works in Docker and breaks behind a
  // prefixed proxy.
  base: './',
  build: {
    outDir: mode === 'check' ? 'dist-check' : '../www',
    emptyOutDir: true,
    // The inherited assets that have to be preserved live in public/ and the
    // build emits them again, so emptying www/ is safe.
  },
  plugins: [react(), staticRoutes()],
}))
