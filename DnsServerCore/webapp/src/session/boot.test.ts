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
  it('devuelve el error del fragmento y limpia la URL', () => {
    setHash('#error=' + encodeURIComponent('SSO authentication failed. Please try again.'))
    expect(readBootIntent()).toEqual({
      kind: 'show-error',
      message: 'SSO authentication failed. Please try again.',
    })
    expect(window.location.hash).toBe('')
  })

  it('el error del fragmento gana a cualquier token guardado', () => {
    localStorage.setItem('token', 'guardado')
    setHash('#error=' + encodeURIComponent('Boom'))
    expect(readBootIntent().kind).toBe('show-error')
  })

  it('toma el token de la cookie y la borra en el acto', () => {
    document.cookie = 'token=de-sso; path=/'
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'de-sso' })
    expect(document.cookie).not.toContain('de-sso')
  })

  it('la cookie gana a localStorage', () => {
    localStorage.setItem('token', 'viejo')
    document.cookie = 'token=nuevo; path=/'
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'nuevo' })
  })

  it('cae a localStorage cuando no hay cookie', () => {
    localStorage.setItem('token', 'guardado')
    expect(readBootIntent()).toEqual({ kind: 'try-token', token: 'guardado' })
  })

  it('sin nada, va al login', () => {
    expect(readBootIntent()).toEqual({ kind: 'show-login' })
  })

  it('limpia la URL aunque no haya error ni token', () => {
    setHash('#loquesea=1')
    readBootIntent()
    expect(window.location.hash).toBe('')
  })
})
