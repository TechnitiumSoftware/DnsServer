import { useEffect, type ReactNode } from 'react'
import './tokens.css'
import './base.css'

/*
Un solo tema: el oscuro. No hay selector ni persistencia porque no hay nada que
elegir; el proveedor sólo fija el atributo para que los tokens apliquen.

Si algún día vuelven los tres temas de upstream, esto recupera su estado y hay
que devolver también el modal `Change Theme` y su entrada del menú de usuario.
*/
export function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    document.documentElement.dataset.theme = 'dark'
  }, [])
  return <>{children}</>
}
