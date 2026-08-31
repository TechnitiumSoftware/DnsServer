import { apiRequest, type ApiOutcome } from './client'
import { urlApi } from '../app/base'

/*
The endpoints of the `user` family. Thirteen in all; this is the phase that
implements them, even though `createSingleUseToken` has no consumers until
phases 4, 5, 6 and 8.
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
main.js:734-740 — the update notice can be silenced persistently, and while it
is silenced the endpoint is NOT EVEN called. Only an explicit `force` skips that
preference.
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
The console's downloads do not go by XHR: a single-use token is asked for and a
window is opened with it in the query. Six places use it (settings backup, log
download and export, zone export, and allowed and blocked export), all of them in
later phases. It lives here because the endpoint belongs to this family.
*/
export async function openDownload(
  token: string | null,
  path: string,
  params: Record<string, string> = {},
  /*
  `ts` is a cache-buster that upstream adds on ONLY TWO of the six downloads
  —the settings backup (main.js:3100) and a log download (logs.js:202)— and not
  on the other four: exporting a zone, exporting allowed, exporting blocked and
  `logs/export` (logs.js:696). The server ignores it, but the URL that gets
  opened is not the same, so where it goes and where it does not is replicated.
  */
  options: { ts?: boolean } = {},
): Promise<{ ok: boolean; url?: string }> {
  const outcome = await apiRequest<{ response: { token: string } }>('user/createSingleUseToken', {
    token,
  })
  if (outcome.kind !== 'ok') return { ok: false }

  const query = new URLSearchParams({
    ...params,
    token: outcome.data.response.token,
  })
  if (options.ts === true) {
    query.set('ts', String(performance.timeOrigin + performance.now()))
  }
  const url = urlApi(`api/${path}?${query.toString()}`)
  window.open(url, '_blank')
  return { ok: true, url }
}
