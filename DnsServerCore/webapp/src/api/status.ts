import { apiRequest } from './client'

/*
`api/status` es público: se llama SIN token, desde la pantalla de login
(main.js:48-60). Gobierna dos comportamientos:

  · ssoEnabled            -> muestra u oculta el botón «Sign in with SSO».
  · hasDefaultCredentials -> en una instalación recién hecha, la consola
                             entra SOLA con admin/admin.

La respuesta viene PLANA, sin envoltorio `response`, igual que login y
session/get. Verificado contra v15.4.
*/
export interface ServerStatus {
  hasDefaultCredentials: boolean
  ssoEnabled: boolean
}

export async function getStatus(): Promise<ServerStatus | null> {
  const outcome = await apiRequest<ServerStatus>('status')
  return outcome.kind === 'ok' ? outcome.data : null
}
