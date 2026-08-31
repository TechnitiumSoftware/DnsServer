import { describe, expect, it } from 'vitest'
import { avisoDeFallo } from './aviso'

/*
The translation of an API failure into an alert was written thirty-six times,
with three different fallbacks for when the server sends no message: "Unknown
error." in Administration, an empty string in DHCP and in Apps, and NOTHING in
the other thirty —that is, a red box with its title and a blank body. `message`
is optional in `ApiOutcome`, so all three were reachable.
*/
describe('avisoDeFallo', () => {
  it('it uses the server message when there is one', () => {
    expect(avisoDeFallo({ kind: 'error', message: 'Zone not found.' })).toEqual({
      type: 'danger',
      title: 'Error!',
      text: 'Zone not found.',
    })
  })

  it('an error with no message does NOT leave the alert blank', () => {
    expect(avisoDeFallo({ kind: 'error' }).text).toBe('Unknown error.')
  })

  it('the expired token says the same thing across the whole console', () => {
    expect(avisoDeFallo({ kind: 'invalid-token' }).text).toBe('Invalid token or session expired.')
  })
})
