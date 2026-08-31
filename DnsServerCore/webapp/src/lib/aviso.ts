import type { AlertType } from '../ui/Alert'

/*
An upstream `showAlert`: a type, a bold title and text. All three are upstream
literals and are not composed with templates.

This type was declared EIGHT times —in Administration, DHCP, Zones, Lists, the
two Logs screens, and under another name in Settings and in Apps— with the same
three properties.
*/
export interface Notice {
  type: AlertType
  title: string
  text: string
}

/*
`showAlert("danger", "Error!", …)`: upstream shows it WHENEVER the response is
not `ok`, with the message the server sends.

The translation was written thirty-six times, with three different fallbacks for
when the server sends no message: "Unknown error." in Administration, an empty
string in DHCP and in Apps, and NOTHING in the other thirty —that is, a red box
with its title and a blank body. `message` is optional in `ApiOutcome`, so all
three were reachable.

"Unknown error." stays, which is the only one of the three that says anything.
*/
export function noticeFromFailure(outcome: { kind: string; message?: string }): Notice {
  return {
    type: 'danger',
    title: 'Error!',
    text:
      outcome.kind === 'error'
        ? (outcome.message ?? 'Unknown error.')
        : 'Invalid token or session expired.',
  }
}
