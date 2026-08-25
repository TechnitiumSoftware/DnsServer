import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// El servidor .NET sirve DnsServerCore/www/ como ficheros estáticos
// (DnsWebService.cs:1832) y honra X-Forwarded-Prefix montando un PathBase
// (DnsWebService.cs:1943-1945). Por eso base debe ser relativa: con base
// absoluta la consola funciona en Docker y rompe tras un proxy con prefijo.
export default defineConfig(({ mode }) => ({
  base: './',
  build: {
    outDir: mode === 'check' ? 'dist-check' : '../www',
    emptyOutDir: true,
    // Los activos heredados que hay que preservar viven en public/ y el build
    // los vuelve a emitir, así que vaciar www/ es seguro.
  },
  plugins: [react()],
}))
