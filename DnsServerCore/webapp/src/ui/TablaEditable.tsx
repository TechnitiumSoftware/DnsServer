import type { ReactNode } from 'react'
import styles from './TablaEditable.module.css'

/*
The table of a list edited in place: the TSIG keys, the forwarders, a scope's
static routes, the SSO group maps, a section's permissions.

It is a different piece from the data table (`ui/Table`) and it must be: that one
is a screen's main object, with its panel and its border; this one lives INSIDE a
panel, up against its fields, and that is why it goes without a box and tighter.
What they share —the small-caps column label— comes from the same tokens.

It exists as a component for the same reason as the other one: the scaffolding was
written five times. Three modules also defined their own class with the same values
copied by hand, and that is where one ended up with 0.07em of letter-spacing and
the rest with 0.05.
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
