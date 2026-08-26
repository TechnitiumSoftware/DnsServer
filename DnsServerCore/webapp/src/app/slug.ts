/*
`Proxy & Forwarders` → `proxy-forwarders`.

Vive suelto y no dentro de `ruta.ts` porque lo necesitan los dos lados: el
navegador para leer la barra de direcciones, y el `vite.config` para saber qué
carpetas tiene que emitir el build. `ruta.ts` toca `window` y `document`, y el
proyecto de TypeScript del config no tiene DOM: una función de cadenas no puede
arrastrar esa dependencia.
*/
export function aSlug(etiqueta: string): string {
  return etiqueta
    .toLowerCase()
    .replace(/&/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}
