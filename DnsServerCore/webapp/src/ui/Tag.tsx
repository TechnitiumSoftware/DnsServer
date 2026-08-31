import type { ReactNode } from 'react'
import styles from './Tag.module.css'

/*
A pill says ONE state. The five tones and what they mean:

  · neutro — a classification fact that is neither good nor bad: `Primary`, `IPv4`
  · ok     — the desirable state: `Enabled`, `Online`
  · warn   — something wants attention but works: `Updating`, `Expiring`
  · dan    — it is broken or switched off: `Disabled`, `Expired`
  · info   — an active feature that is not a judgement: `DNSSEC`

No pill is painted outside this: counts go in the bar above the table, not in a
capsule with this same look.
*/

export type TagTone = 'neutral' | 'ok' | 'warn' | 'dan' | 'info'

export function Tag({ tone = 'neutral', children }: { tone?: TagTone; children: ReactNode }) {
  return (
    <span className={`${styles.tag}${tone === 'neutral' ? '' : ` ${styles[tone]}`}`}>
      {children}
    </span>
  )
}

/** The code chip: a record type, an app's class. Neither round nor coloured: it
 *  does not say whether something is good or bad, it says WHAT it is. */
export function Chip({ children }: { children: ReactNode }) {
  return <span className={styles.chip}>{children}</span>
}
