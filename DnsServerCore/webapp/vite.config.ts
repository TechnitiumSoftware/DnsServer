import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { STATIC_ROUTES } from './src/app/static-routes.js'

/*
Una carpeta con su `index.html` por cada route de la consola.

El servidor sirve `www/` con ficheros estáticos y `UseDefaultFiles()`
(DnsWebService.cs:1960): `/settings/logging/` se resuelve a
`/settings/logging/index.html`, y `/settings/logging` recibe un 301 a la versión
con barra. Con el fichero puesto, la URL es real —nada de `#/`— y un F5 vuelve
donde estabas, **sin tocar una línea de C#**.

Las rutas de los activos se corrigen a la profundidad de cada copia (`../` o
`../../`). No es cosmética: `base` es relativa a propósito —el servidor honra
`X-Forwarded-Prefix` montando un `PathBase`, y con base absoluta la consola se
rompe tras un proxy con prefijo—, así que la única forma de que
`/dns/settings/logging/` encuentre `/dns/assets/…` es contar los saltos.

Y cada copia lleva su route en un `<meta>`, que es lo que permite a la aplicación
saber cuál es su raíz sin conocer el prefijo: la raíz es su `pathname` menos esos
segmentos.
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
