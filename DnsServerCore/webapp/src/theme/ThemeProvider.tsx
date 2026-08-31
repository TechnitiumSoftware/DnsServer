import { useEffect, type ReactNode } from 'react'
import './tokens.css'
import './base.css'

/*
A single theme: the dark one. There is no picker and no persistence because there
is nothing to choose; the provider only sets the attribute so the tokens apply.

If upstream's three themes ever come back, this regains its state and the
`Change Theme` modal and its account-menu entry have to come back too.
*/
export function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    document.documentElement.dataset.theme = 'dark'
  }, [])
  return <>{children}</>
}
