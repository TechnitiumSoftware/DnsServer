import type { ButtonHTMLAttributes } from 'react'
import styles from './Button.module.css'

export type ButtonVariant = 'primary' | 'secondary' | 'danger'

export function Button({
  variant = 'secondary',
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const variantClass = variant === 'secondary' ? '' : styles[variant]
  return <button className={[styles.btn, variantClass, className].filter(Boolean).join(' ')} {...rest} />
}
