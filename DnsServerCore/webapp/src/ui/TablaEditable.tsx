import type { ReactNode } from 'react'
import styles from './TablaEditable.module.css'

/*
La tabla de una lista que se edita en el sitio: las claves TSIG, los
reenviadores, las rutas estáticas de un scope, los mapas de grupos de SSO, los
permisos de una sección.

Es otra pieza que la tabla de datos (`ui/Table`) y debe serlo: aquella es el
objeto principal de una pantalla, con su panel y su borde; ésta vive DENTRO de
un panel, pegada a sus campos, y por eso va sin caja y más apretada. Lo que
comparten —el rótulo de columna en versalitas— sale de los mismos tokens.

Existe como componente por lo mismo que la otra: el andamiaje estaba escrito
cinco veces. Tres módulos definían además su propia clase con los mismos valores
copiados a mano, y ahí es donde una acabó con 0.07em de interletrado y las demás
con 0.05.
*/
export function TablaEditable({
  cabecera,
  children,
  className,
}: {
  cabecera: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <table className={[styles.tabla, className].filter(Boolean).join(' ')}>
      <thead>
        <tr>{cabecera}</tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  )
}
