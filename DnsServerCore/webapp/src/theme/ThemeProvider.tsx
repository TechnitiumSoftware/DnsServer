import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import './tokens.css'

export type Theme = 'dark' | 'light' | 'amber'

export const THEMES: Theme[] = ['dark', 'light', 'amber']

function isTheme(value: unknown): value is Theme {
  return typeof value === 'string' && (THEMES as string[]).includes(value)
}

interface ThemeContextValue {
  theme: Theme
  setTheme: (t: Theme) => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('theme')
    return isTheme(saved) ? saved : 'dark'
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('theme', theme)
  }, [theme])

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme se ha usado fuera de ThemeProvider')
  return ctx
}
