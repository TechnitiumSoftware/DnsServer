import type { ReactNode } from 'react'
import styles from './Empty.module.css'

/*
Un vacío se pinta de dos maneras y no más:

  · `Empty` — el vacío de una REGIÓN, el que ocupa el sitio de la tabla o la
    rejilla que no tiene filas. Caja de puntos, centrado, con título y, si el
    usuario puede hacer algo al respecto, el botón que lo hace.
  · `Empty compacto` — el vacío de DENTRO de un panel, una línea apagada que no
    compite con el panel que la contiene.

Y `Loading` y `Fallo` son el mismo hueco antes del dato: uno mientras viaja y
otro cuando no llegó. Mismo sitio y mismo peso que el vacío al que sustituyen,
para que la pantalla no salte al resolverse.

`Fallo` estaba escrito a mano en cuatro módulos —`.fail` en Settings, DHCP, Logs
y Administration— con los mismos cuatro valores que ya tenía `.cargando` aquí.
*/

export function Empty({
  titulo,
  children,
  acciones,
  compacto = false,
}: {
  /** Qué es lo que no hay. Sólo en el vacío de región. */
  titulo?: string
  /** Por qué no lo hay, o qué hacer para que lo haya. */
  children?: ReactNode
  acciones?: ReactNode
  compacto?: boolean
}) {
  if (compacto) return <div className={styles.linea}>{children}</div>

  return (
    <div className={styles.caja}>
      {titulo != null && <span className={styles.titulo}>{titulo}</span>}
      {children}
      {acciones != null && <div className={styles.acciones}>{acciones}</div>}
    </div>
  )
}

export function Loading({
  children = 'Loading…',
  compacto = false,
}: {
  /** Qué se está cargando, cuando decirlo ayuda: «Loading DS records…». */
  children?: ReactNode
  compacto?: boolean
}) {
  return <div className={`${styles.cargando}${compacto ? ` ${styles.linea}` : ''}`}>{children}</div>
}

/** El dato no llegó. Ocupa el mismo hueco que el `Loading` al que sustituye. */
export function Fallo({ children }: { children: ReactNode }) {
  return <div className={styles.cargando}>{children}</div>
}
