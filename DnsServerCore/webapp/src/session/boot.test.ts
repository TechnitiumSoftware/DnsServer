import { describe, expect, it, beforeEach } from 'vitest'
import { readBootIntent } from './boot'

function setHash(h: string) {
  window.history.replaceState(null, '', '/' + h)
}

beforeEach(() => {
  setHash('')
  localStorage.clear()
  document.cookie = 'token=; max-age=0; path=/'
})

describe('readBootIntent', () => {
  it('it returns the fragment error and cleans the URL', () => {
    setHash('#error=' + encodeURIComponent('SSO authentication failed. Please try again.'))
    expect(readBootIntent()).toEqual({
      kind: 'show-error',
      message: 'SSO authentication failed. Please try again.',
    })
    expect(window.location.hash).toBe('')
  })

  it('the fragment error wins over any stored token', () => {
    localStorage.setItem('token', 'guardado')
    setHash('#error=' + encodeURIComponent('Boom'))
    expect(readBootIntent().kind).toBe('show-error')
  })

  it('it takes the token from the cookie and deletes it on the spot', () => {
    document.cookie = 'token=de-sso; path=/'
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'de-sso' })
    expect(document.cookie).not.toContain('de-sso')
  })

  it('the cookie wins over localStorage', () => {
    localStorage.setItem('token', 'viejo')
    document.cookie = 'token=nuevo; path=/'
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'nuevo' })
  })

  it('it falls back to localStorage when there is no cookie', () => {
    localStorage.setItem('token', 'guardado')
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'guardado' })
  })

  it('with nothing, it goes to the login', () => {
    expect(readBootIntent()).toEqual({ kind: 'show-login' })
  })

  it('it cleans the URL even with no error and no token', () => {
    setHash('#loquesea=1')
    readBootIntent()
    expect(window.location.hash).toBe('')
  })
})
