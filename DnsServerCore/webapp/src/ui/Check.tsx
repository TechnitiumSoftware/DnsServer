import type { ReactNode } from 'react'
import styles from './Check.module.css'

/*
La casilla con etiqueta y ayuda. Estaba escrita tres veces —Settings, DHCP y
Administration— byte a byte igual salvo el módulo de estilos.

Y trae el **conmutador**, que es el único gesto propio que se ha permitido esta
consola. Un ajuste de sí/no no es lo mismo que marcar una fila de una tabla: el
primero cambia cómo se comporta el servidor y se queda así, el segundo es una
selección que dura un clic. Upstream los pinta iguales porque Bootstrap 3 sólo
tenía casilla. Aquí el ajuste lleva conmutador y la selección sigue siendo
casilla, que es la diferencia que la forma tenía que decir y no decía.

Por debajo sigue siendo un `input[type=checkbox]`: mismo teclado, mismo rol,
mismas pruebas. Lo que cambia es lo que se ve.
*/

export function Check({
  label,
  checked,
  onChange,
  help,
  disabled,
  conmutador = false,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
  help?: ReactNode
  disabled?: boolean
  /** Un ajuste que se queda puesto. Falso para una selección de fila. */
  conmutador?: boolean
}) {
  return (
    <div className={conmutador ? styles.conmutador : undefined}>
      <label className={styles.check}>
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className={styles.texto}>{label}</span>
      </label>
      {help && <div className={styles.ayuda}>{help}</div>}
    </div>
  )
}
