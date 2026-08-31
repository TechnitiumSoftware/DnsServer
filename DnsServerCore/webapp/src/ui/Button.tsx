import type { ButtonHTMLAttributes, Ref } from 'react'
import styles from './Button.module.css'

export type ButtonVariant = 'primary' | 'secondary' | 'danger'

/*
`size="sm"` is the button for a table row. It existed as `.ib` copied across three
modules and did not exist in DHCP, which used the large button: the same action
—"Edit"— looked different depending on which screen you were on.
*/
export function Button({
  variant = 'secondary',
  size = 'md',
  icono = false,
  className,
  ref,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: 'md' | 'sm'
  /** No label: an icon only. The width comes from the icon, not from text. */
  icono?: boolean
  ref?: Ref<HTMLButtonElement>
}) {
  return (
    <button
      ref={ref}
      data-variant={variant}
      data-icono={icono || undefined}
      className={[styles.btn, size === 'sm' && styles.sm, variant !== 'secondary' && styles[variant], className]
        .filter(Boolean)
        .join(' ')}
      {...rest}
    />
  )
}
