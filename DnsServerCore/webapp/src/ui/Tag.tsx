import type { ReactNode } from 'react'
import styles from './Tag.module.css'

/*
Una píldora dice UN estado. Los cinco tonos y lo que significan:

  · neutro — un dato de clasificación que no es bueno ni malo: `Primary`, `IPv4`
  · ok     — el estado deseable: `Enabled`, `Online`
  · warn   — algo pide atención pero funciona: `Updating`, `Expiring`
  · dan    — está roto o apagado: `Disabled`, `Expired`
  · info   — una característica activa que no es un juicio: `DNSSEC`

Fuera de aquí no se pinta ninguna píldora: los recuentos van en la barra sobre
la tabla, no en una cápsula con este mismo aspecto.
*/

export type TagTone = 'neutral' | 'ok' | 'warn' | 'dan' | 'info'

export function Tag({ tone = 'neutral', children }: { tone?: TagTone; children: ReactNode }) {
  return (
    <span className={`${styles.tag}${tone === 'neutral' ? '' : ` ${styles[tone]}`}`}>
      {children}
    </span>
  )
}

/** El chip de código: tipo de registro, clase de un app. Ni redondo ni de color:
 *  no dice si algo está bien o mal, dice QUÉ es. */
export function Chip({ children }: { children: ReactNode }) {
  return <span className={styles.chip}>{children}</span>
}
