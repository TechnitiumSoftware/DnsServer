import { useEffect, useRef, useState, type ReactNode } from 'react'
import styles from './Zones.module.css'

/*
El menú «⋮» de cada fila. Upstream lo resuelve con el dropdown de Bootstrap 3;
aquí es un botón con una lista que se cierra al pulsar fuera o con Escape.

No usa Radix a propósito: `DropdownMenu` traería una dependencia nueva a
`package.json` para un componente de veinte líneas, y las primitivas del
proyecto son deliberadamente pocas.
*/

export function Menu({
  etiqueta,
  rotulo,
  children,
}: {
  /** Nombre accesible; es lo único que hay cuando no lleva rótulo visible. */
  etiqueta: string
  /** Texto visible. Sin él, el botón es el «⋮» compacto de una fila. */
  rotulo?: string
  children: (cerrar: () => void) => ReactNode
}) {
  const [abierto, setAbierto] = useState(false)
  const caja = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!abierto) return

    function fuera(e: MouseEvent) {
      if (caja.current && !caja.current.contains(e.target as Node)) setAbierto(false)
    }
    function escape(e: KeyboardEvent) {
      if (e.key === 'Escape') setAbierto(false)
    }

    document.addEventListener('mousedown', fuera)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', fuera)
      document.removeEventListener('keydown', escape)
    }
  }, [abierto])

  return (
    <div className={styles.menu} ref={caja}>
      <button
        type="button"
        className={styles.ib}
        aria-haspopup="menu"
        aria-expanded={abierto}
        aria-label={etiqueta}
        onClick={() => setAbierto((v) => !v)}
      >
        {rotulo == null ? '⋮' : `${rotulo} ▾`}
      </button>
      {abierto && (
        <div className={styles.menuLista} role="menu">
          {children(() => setAbierto(false))}
        </div>
      )}
    </div>
  )
}

export function Separador() {
  return <div className={styles.sep} role="separator" />
}
