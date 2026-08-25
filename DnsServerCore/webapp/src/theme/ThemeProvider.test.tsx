import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider, useTheme } from './ThemeProvider'

function Probe() {
  const { theme, setTheme } = useTheme()
  return (
    <>
      <span data-testid="t">{theme}</span>
      <button onClick={() => setTheme('light')}>claro</button>
      <button onClick={() => setTheme('amber')}>ambar</button>
    </>
  )
}

beforeEach(() => {
  localStorage.clear()
  delete document.documentElement.dataset.theme
})

describe('ThemeProvider', () => {
  it('arranca en oscuro', () => {
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(screen.getByTestId('t')).toHaveTextContent('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('cambia y persiste', async () => {
    render(<ThemeProvider><Probe /></ThemeProvider>)
    await userEvent.click(screen.getByText('claro'))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('theme')).toBe('light')
  })

  it('recupera el tema guardado', () => {
    localStorage.setItem('theme', 'amber')
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(screen.getByTestId('t')).toHaveTextContent('amber')
  })

  it('ignora un valor guardado que no sea un tema', () => {
    localStorage.setItem('theme', 'fucsia')
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(screen.getByTestId('t')).toHaveTextContent('dark')
  })

  it('los tres temas siguen existiendo: borrarlos seria quitar funcionalidad', async () => {
    render(<ThemeProvider><Probe /></ThemeProvider>)
    await userEvent.click(screen.getByText('ambar'))
    expect(document.documentElement.dataset.theme).toBe('amber')
    await userEvent.click(screen.getByText('claro'))
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})
