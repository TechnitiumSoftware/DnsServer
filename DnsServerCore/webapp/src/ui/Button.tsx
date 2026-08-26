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
  icono = false,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: 'md' | 'sm'
  /** Sin rótulo: sólo un icono. El ancho lo da el icono, no el texto. */
  icono?: boolean
}) {
  return (
    <button
      data-variant={variant}
      data-icono={icono || undefined}
      className={[styles.btn, size === 'sm' && styles.sm, variant !== 'secondary' && styles[variant], className]
        .filter(Boolean)
        .join(' ')}
      {...rest}
    />
  )
}
