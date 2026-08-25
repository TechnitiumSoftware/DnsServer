import { apiRequest, type ApiOutcome } from './client'

/*
Los endpoints de la familia `user`. Trece en total; ésta es la fase que los
implementa, aunque `createSingleUseToken` no tenga consumidores hasta las fases
4, 5, 6 y 8.
*/

export interface SessionRow {
  username: string
  isCurrentSession: boolean
  partialToken: string
  type: string
  tokenName: string | null
  lastSeen: string
  lastSeenRemoteAddress: string
  lastSeenUserAgent: string
}

export function deleteSession(token: string | null, partialToken: string): Promise<ApiOutcome> {
  return apiRequest('user/session/delete', { token, body: { partialToken } })
}

/*
main.js:734-740 — el aviso de actualización se puede silenciar de forma
persistente, y cuando está silenciado NI SIQUIERA se llama al endpoint. Sólo un
`force` explícito se salta esa preferencia.
*/
export const DISABLE_UPDATE_NOTIFICATION_KEY = 'disableUpdateNotification'

export async function checkForUpdate(
  token: string | null,
  force = false,
): Promise<ApiOutcome<{ response: { updateAvailable: boolean } }> | { kind: 'skipped' }> {
  if (!force && localStorage.getItem(DISABLE_UPDATE_NOTIFICATION_KEY) === 'true') {
    return { kind: 'skipped' }
  }
  return apiRequest('user/checkForUpdate', { token })
}

/*
Las descargas de la consola no van por XHR: se pide un token de un solo uso y se
abre una ventana con él en la query. Lo usan seis sitios (backup de ajustes,
descarga y exportación de logs, export de zona, y export de allowed y blocked),
todos en fases posteriores. Vive aquí porque el endpoint es de esta familia.
*/
export async function openDownload(
  token: string | null,
  path: string,
  params: Record<string, string> = {},
): Promise<{ ok: boolean; url?: string }> {
  const outcome = await apiRequest<{ response: { token: string } }>('user/createSingleUseToken', {
    token,
  })
  if (outcome.kind !== 'ok') return { ok: false }

  const query = new URLSearchParams({
    ...params,
    token: outcome.data.response.token,
    ts: String(performance.timeOrigin + performance.now()),
  })
  const url = `api/${path}?${query.toString()}`
  window.open(url, '_blank')
  return { ok: true, url }
}
