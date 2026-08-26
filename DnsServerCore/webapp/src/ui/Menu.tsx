import { Button } from './Button'
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import styles from './Menu.module.css'
import { Icono } from './Icono'

/*
El menú «⋮» de cada fila. Upstream lo resuelve con el dropdown de Bootstrap 3;
aquí es un botón con una lista que se cierra al pulsar fuera o con Escape.

Vivía dentro de Zones y ahora es de todos, porque la regla que ordena las
acciones de fila lo necesita en todas las tablas: **lo destructivo va aquí
dentro**. En una fila no puede haber un «Delete» suelto al lado de un
«Disable» —son doscientas cuarenta filas y esta consola no tiene deshacer en
ninguna parte—, así que borrar cuesta abrir el menú. En una pantalla de detalle
sí va fuera: allí actúas sobre un objeto que estás mirando.

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
  const [caja, setCaja] = useState<{ right: number; top: number } | null>(null)
  const disparador = useRef<HTMLButtonElement>(null)
  const lista = useRef<HTMLDivElement>(null)

  /*
  La lista va en `position: fixed`, medida desde el disparador, y NO absoluta
  dentro de la fila. Absoluta no valía: la recortaban dos contenedores a la vez
  —el grupo segmentado de acciones, que lleva `overflow: hidden` por sus
  esquinas, y el envoltorio de la tabla, que lleva `overflow-x: auto`—, así que
  el menú se abría y no se veía. Es el mismo motivo por el que `ui/Select` la
  saca fija, y por el mismo motivo se cierra al rodar la página.
  */
  useLayoutEffect(() => {
    if (!abierto) { setCaja(null); return }
    const r = disparador.current?.getBoundingClientRect()
    if (r != null) setCaja({ right: window.innerWidth - r.right, top: r.bottom + 4 })
  }, [abierto])

  useEffect(() => {
    if (!abierto) return

    function fuera(e: MouseEvent) {
      const t = e.target as Node
      if (!disparador.current?.contains(t) && !lista.current?.contains(t)) setAbierto(false)
    }
    function escape(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setAbierto(false)
        disparador.current?.focus()
      }
    }
    const alRodar = () => setAbierto(false)

    document.addEventListener('mousedown', fuera)
    document.addEventListener('keydown', escape)
    window.addEventListener('scroll', alRodar, true)
    window.addEventListener('resize', alRodar)
    return () => {
      document.removeEventListener('mousedown', fuera)
      document.removeEventListener('keydown', escape)
      window.removeEventListener('scroll', alRodar, true)
      window.removeEventListener('resize', alRodar)
    }
  }, [abierto])

  return (
    <div className={styles.menu}>
      <Button
        ref={disparador}
        size="sm"
        icono={rotulo == null}
        aria-haspopup="menu"
        aria-expanded={abierto}
        aria-label={etiqueta}
        onClick={() => setAbierto((v) => !v)}
      >
        {rotulo == null ? (
          <Icono nombre="mas" tam={16} />
        ) : (
          <>
            {rotulo}
            <Icono nombre="chevronAbajo" tam={12} />
          </>
        )}
      </Button>
      {abierto && caja && (
        <div className={styles.menuLista} role="menu" ref={lista} style={caja}>
          {children(() => setAbierto(false))}
        </div>
      )}
    </div>
  )
}

export function Separador() {
  return <div className={styles.sep} role="separator" />
}
