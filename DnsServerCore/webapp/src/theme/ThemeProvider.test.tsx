import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { ThemeProvider } from './ThemeProvider'

describe('ThemeProvider', () => {
  it('fija el tema oscuro', () => {
    render(<ThemeProvider><span>hola</span></ThemeProvider>)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('no guarda preferencia de tema: no hay nada que elegir', () => {
    localStorage.clear()
    render(<ThemeProvider><span>hola</span></ThemeProvider>)
    expect(localStorage.getItem('theme')).toBeNull()
  })
})
