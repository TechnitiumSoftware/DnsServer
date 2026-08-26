import type { ReactNode } from 'react'
import styles from './Empty.module.css'

/*
Un vacío se pinta de dos maneras y no más:

  · `Empty` — el vacío de una REGIÓN, el que ocupa el sitio de la tabla o la
    rejilla que no tiene filas. Caja de puntos, centrado, con título y, si el
    usuario puede hacer algo al respecto, el botón que lo hace.
  · `Empty compacto` — el vacío de DENTRO de un panel, una línea apagada que no
    compite con el panel que la contiene.

Y `Loading` es el mismo hueco mientras el dato viaja: mismo sitio, mismo peso.
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
