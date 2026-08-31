import type { ReactNode } from 'react'
import styles from './Check.module.css'

/*
The checkbox with its label and help. It was written three times —Settings, DHCP
and Administration— byte for byte identical apart from the styles module.

And it brings the **switch**, which is the only gesture of its own this console has
allowed itself. A yes/no setting is not the same as ticking a table row: the first
changes how the server behaves and stays that way, the second is a selection that
lasts one click. Upstream paints them the same because Bootstrap 3 only had a
checkbox. Here the setting gets a switch and the selection stays a checkbox, which
is the difference the shape had to say and was not saying.

Underneath it is still an `input[type=checkbox]`: same keyboard, same role, same
tests. What changes is what you see.
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
  /** A setting that stays put. False for a row selection. */
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
        <span className={styles.text}>{label}</span>
      </label>
      {help && <div className={styles.help}>{help}</div>}
    </div>
  )
}
