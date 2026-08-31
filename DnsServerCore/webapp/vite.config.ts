import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { RUTAS_ESTATICAS } from './src/app/static-routes.js'

/*
Una carpeta con su `index.html` por cada ruta de la consola.

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

Y cada copia lleva su ruta en un `<meta>`, que es lo que permite a la aplicación
saber cuál es su raíz sin conocer el prefijo: la raíz es su `pathname` menos esos
segmentos.
*/
function rutasEstaticas(): Plugin {
  return {
    name: 'rutas-estaticas',
    enforce: 'post',
    generateBundle(_opciones, paquete) {
      const indice = paquete['index.html']
      if (indice == null || indice.type !== 'asset') return

      for (const ruta of RUTAS_ESTATICAS) {
        const saltos = '../'.repeat(ruta.split('/').length)
        const html = String(indice.source)
          .replace(/(href|src)="\.\//g, `$1="${saltos}`)
          .replace('<head>', `<head>\n    <meta name="ruta" content="${ruta}" />`)

        this.emitFile({ type: 'asset', fileName: `${ruta}/index.html`, source: html })
      }
    },
  }
}

export default defineConfig(({ mode }) => ({
  // El servidor .NET sirve DnsServerCore/www/ como ficheros estáticos
  // (DnsWebService.cs:1832) y honra X-Forwarded-Prefix montando un PathBase
  // (DnsWebService.cs:1943-1945). Por eso base debe ser relativa: con base
  // absoluta la consola funciona en Docker y rompe tras un proxy con prefijo.
  base: './',
  build: {
    outDir: mode === 'check' ? 'dist-check' : '../www',
    emptyOutDir: true,
    // Los activos heredados que hay que preservar viven en public/ y el build
    // los vuelve a emitir, así que vaciar www/ es seguro.
  },
  plugins: [react(), rutasEstaticas()],
}))
