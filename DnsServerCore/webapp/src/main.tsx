import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { urlPublica } from './app/base'

/*
The icon is anchored before anything else.

In the HTML it goes as `./favicon.ico` —relative, because the console can hang off
any prefix (see `app/ruta.ts`)— and the browser resolves it LATE, against
whatever address is current at that moment. Since the application normalises the
route as soon as it starts (`/settings/` → `/settings/general/`), the resolution
landed one level below and asked for `/settings/favicon.ico`: a 404 on every
route that is not the root.

Pinning it here makes it absolute once, with the root already deduced, and it
stops depending on what the address bar says afterwards.
*/
document.querySelector<HTMLLinkElement>('link[rel="icon"]')?.setAttribute('href', urlPublica('favicon.ico'))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
