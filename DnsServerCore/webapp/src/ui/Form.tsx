import { useId, type ReactNode } from 'react'
import frm from './Form.module.css'

/*
A form row: label on the left, control on the right.

It was written by hand 38 times, and on top of that existed TWICE as a component
—in `screens/settings/parts.tsx` and in `screens/dhcp/parts.tsx`, byte-identical
apart from one comment— without any of the other twelve screens using either. With
the row loose, the pieces around it drifted apart too: the help under a field and
the checkbox group were each defined three times.

`modal` changes the grid: inside a dialog there is less room and fewer rows, so the
label column is narrower and carries no separator. That is the only real
difference between the two variants, which is why it is a parameter and not
another component.
*/
export function Row({
  label,
  help,
  modal = false,
  children,
}: {
  label: string
  help?: ReactNode
  modal?: boolean
  /** Receives the `id` to put on the control, so the label governs it. */
  children: (id: string) => ReactNode
}) {
  const id = useId()
  return (
    <div className={modal ? frm.mrow : frm.row}>
      <label className={modal ? frm.mrowLabel : frm.rowLabel} htmlFor={id}>
        {label}
      </label>
      <div className={modal ? frm.mrowCtl : frm.rowCtl}>
        {children(id)}
        {help != null && <div className={frm.help}>{help}</div>}
      </div>
    </div>
  )
}

/**
 * A row whose label governs no single control —checkbox and radio groups—:
 * upstream uses a `<label>` with no `for` there, because pointing it at one of the
 * group's controls would lie about what it refers to.
 */
export function GroupRow({
  label,
  help,
  modal = false,
  children,
}: {
  label: string
  help?: ReactNode
  modal?: boolean
  children: ReactNode
}) {
  return (
    <div className={modal ? frm.mrow : frm.row}>
      <div className={modal ? frm.mrowLabel : frm.rowLabel}>{label}</div>
      <div className={modal ? frm.mrowCtl : frm.rowCtl}>
        <div className={frm.group}>{children}</div>
        {help != null && <div className={frm.help}>{help}</div>}
      </div>
    </div>
  )
}

/** The standalone help, for when it does not hang off a row. */
export function HelpText({ children }: { children: ReactNode }) {
  return <div className={frm.help}>{children}</div>
}
