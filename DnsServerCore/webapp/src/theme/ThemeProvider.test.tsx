import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { ThemeProvider } from './ThemeProvider'

describe('ThemeProvider', () => {
  it('it pins the dark theme', () => {
    render(<ThemeProvider><span>hola</span></ThemeProvider>)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('it stores no theme preference: there is nothing to choose', () => {
    localStorage.clear()
    render(<ThemeProvider><span>hola</span></ThemeProvider>)
    expect(localStorage.getItem('theme')).toBeNull()
  })
})
