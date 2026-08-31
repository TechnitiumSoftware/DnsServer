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
  onAbrir,
  children,
}: {
  /** Nombre accesible; es lo único que hay cuando no lleva rótulo visible. */
  etiqueta: string
  /** Texto visible. Sin él, el botón es el «⋮» compacto de una fila. */
  rotulo?: string
  /**
   * Se avisa al abrir, para el menú que necesita saber el estado del servidor
   * justo antes de enseñar sus opciones. Upstream hace lo mismo con el de
   * bloqueo del Dashboard (`main.js:2429`): pregunta al abrir, no al pintar,
   * porque entre una cosa y otra el ajuste puede haber cambiado en otra
   * pestaña.
   */
  onAbrir?: () => void
  children: (cerrar: () => void) => ReactNode
}) {
  const [abierto, setAbierto] = useState(false)
  const [caja, setCaja] = useState<
    { right: number; top?: number; bottom?: number; maxHeight: number } | null
  >(null)
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
  /*
  Y se abre hacia donde quepa. Un menú largo colgado de un disparador bajo se
  salía por debajo: el de bloqueo del Dashboard son nueve opciones sobre un panel
  a media pantalla, y las tres últimas quedaban fuera de la ventana. Sin salida,
  además, porque este menú se cierra al rodar la página.

  Así que si abajo no cabe y arriba hay más sitio, se ancla por el borde de
  abajo; y en cualquier caso se le pone el alto disponible como tope, con la
  lista rodando por dentro. Lo segundo es el cinturón: aunque no quepa en
  ninguno de los dos lados —una ventana muy baja—, todas las opciones siguen
  siendo alcanzables.
  */
  useLayoutEffect(() => {
    if (!abierto) { setCaja(null); return }
    const r = disparador.current?.getBoundingClientRect()
    if (r == null) return

    const MARGEN = 8
    const debajo = window.innerHeight - r.bottom - MARGEN
    const encima = r.top - MARGEN
    const right = window.innerWidth - r.right

    setCaja(
      debajo < encima && debajo < 240
        ? { right, bottom: window.innerHeight - r.top + 4, maxHeight: encima }
        : { right, top: r.bottom + 4, maxHeight: debajo },
    )
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
    /* Rodar la página lo cierra, pero rodar la propia lista no: desde que la
       lista puede tener tope de alto, ese scroll es suyo.

       El `instanceof` no sobra: este mismo manejador atiende al `resize`, y ahí
       el `target` es `window`, que no es un nodo. Sin la guarda, `contains()`
       lanzaba en cada cambio de tamaño con un menú abierto. */
    const alRodar = (e: Event) => {
      if (e.target instanceof Node && lista.current?.contains(e.target)) return
      setAbierto(false)
    }

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
        onClick={() => {
          if (!abierto) onAbrir?.()
          setAbierto((v) => !v)
        }}
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
