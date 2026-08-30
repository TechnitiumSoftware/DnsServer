import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { urlPublica } from './app/base'

/*
El icono se ancla antes de nada.

En el HTML va como `./favicon.ico` —relativo, porque la consola puede colgar de
cualquier prefijo (ver `app/ruta.ts`)—, y el navegador lo resuelve TARDE, contra
la dirección que haya en ese momento. Como la aplicación normaliza la ruta nada
más arrancar (`/settings/` → `/settings/general/`), la resolución caía un nivel
por debajo y pedía `/settings/favicon.ico`: 404 en toda ruta que no sea la raíz.

Fijarlo aquí lo convierte en absoluto una sola vez, con la raíz ya deducida, y
deja de depender de lo que diga la barra de direcciones después.
*/
document.querySelector<HTMLLinkElement>('link[rel="icon"]')?.setAttribute('href', urlPublica('favicon.ico'))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
