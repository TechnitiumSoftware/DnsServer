import { apiRequest } from './client'

/*
`api/status` is public: it is called WITHOUT a token, from the login screen
(main.js:48-60). It governs two behaviours:

  · ssoEnabled            -> shows or hides the "Sign in with SSO" button.
  · hasDefaultCredentials -> on a fresh install, the console logs itself IN with
                             admin/admin.

The response comes FLAT, with no `response` wrapper, same as login and
session/get. Verified against v15.4.
*/
export interface ServerStatus {
  hasDefaultCredentials: boolean
  ssoEnabled: boolean
}

export async function getStatus(): Promise<ServerStatus | null> {
  const outcome = await apiRequest<ServerStatus>('status')
  return outcome.kind === 'ok' ? outcome.data : null
}
