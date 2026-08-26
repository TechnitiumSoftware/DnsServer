/* Las extensiones `.js` son deliberadas: este fichero lo compila también el
   proyecto de TypeScript del `vite.config`, que usa resolución `nodenext` y las
   exige. El proyecto de la aplicación las resuelve igual. */
import { SECTIONS } from './sections.js'
import { aSlug } from './slug.js'

/*
Las rutas que el build tiene que materializar como carpeta.

La consola se sirve como ficheros estáticos: `UseDefaultFiles()` mapea `/zones/`
a `/zones/index.html` y redirige `/zones` con un 301, así que basta con que ese
fichero exista para que `dns.shlab.app/settings/logging/` funcione y sobreviva a
un F5. Es la misma técnica con la que cualquier generador de sitios estáticos
publica un sitio sin configurar el servidor.

Vive en `src/` y no en el `vite.config` porque la lista sale de `SECTIONS`: si
mañana aparece una sub-sección nueva, su carpeta se genera sola.
*/
export const RUTAS_ESTATICAS: string[] = SECTIONS.flatMap((s) => [
  s.id,
  ...(s.subs ?? []).map((t) => `${s.id}/${aSlug(t)}`),
])
