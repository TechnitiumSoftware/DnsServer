import type { ButtonHTMLAttributes } from 'react'
import styles from './Button.module.css'

export type ButtonVariant = 'primary' | 'secondary' | 'danger'

/*
`size="sm"` es el botón de una fila de tabla. Existía como `.ib` copiada en
tres módulos y no existía en DHCP, que usaba el botón grande: la misma acción
—«Edit»— se veía distinta según la pantalla en la que estuvieras.
*/
export function Button({
  variant = 'secondary',
  size = 'md',
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: 'md' | 'sm'
}) {
  return (
    <button
      className={[styles.btn, size === 'sm' && styles.sm, variant !== 'secondary' && styles[variant], className]
        .filter(Boolean)
        .join(' ')}
      {...rest}
    />
  )
}
