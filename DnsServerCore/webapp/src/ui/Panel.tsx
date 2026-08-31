import { useId, type ReactNode } from 'react'
import styles from './Panel.module.css'

/*
The console's bordered box: ONE component, not a class each screen applies on its
own.

This used to be a `<fieldset>` with a `<legend>` as its header, and it did not
work: a `legend` measures its `width: 100%` against the fieldset's CONTENT box,
and the browser reserves that fieldset a side padding of its own that nobody had
removed. The title band ended up 21 px narrower than the card, floating inside
instead of touching the edges. It was patched over with `float: left`, which is
exactly the kind of patch that appears when you unify through CSS instead of
through a component.

With a `div` the header is an ordinary child and the band reaches the edge with no
tricks. The group is still announced: `role="group"` with `aria-labelledby` is
what the ARIA specification gives as the equivalent of `fieldset`/`legend`, and it
is also what upstream does, using `div.panel` with its title and no `fieldset`.
*/
export function Panel({
  titulo,
  acciones,
  agrupa = false,
  children,
  className,
}: {
  /*
  With no title, the panel just groups: no label is invented for it.

  It takes a node and not only a string because some titles carry formatting —the
  log viewer puts the file name in monospace— and a component that only accepts
  plain text forces the screen to skip it and replicate the markup, which is
  exactly what this exists to avoid.
  */
  titulo?: ReactNode
  /** What goes on the right of the header. */
  acciones?: ReactNode
  /*
  Announce the panel as a named GROUP. Only where it really does group related
  controls —the Settings and DHCP blocks, which are what used to be a `fieldset`—;
  not on a panel containing a chart or a table, where the `h2` already provides
  the structure and the role is redundant.

  This is not cosmetic: applied to all of them, the "Query Response Types" panel
  ended up named the same as the chart it contains, and a screen reader said the
  same name twice in a row.
  */
  agrupa?: boolean
  children: ReactNode
  className?: string
}) {
  const id = useId()
  const clases = [styles.panel, titulo == null ? styles.sinCabecera : null, className]
    .filter(Boolean)
    .join(' ')

  if (titulo == null) return <div className={clases}>{children}</div>

  return (
    <div className={clases} role={agrupa ? 'group' : undefined} aria-labelledby={agrupa ? id : undefined}>
      <div className={styles.cabecera}>
        <h2 className={styles.titulo} id={id}>
          {titulo}
        </h2>
        {acciones}
      </div>
      {children}
    </div>
  )
}

/*
The panel body: the padding that separates the content from its edges.

It goes as a component and not as a class each screen composes, for the same
reason as the panel: what is shared is the PIECE, not a loose rule. It is optional
because some panels have content that reaches the edges on purpose —the Settings
blocks, whose rows bring their own padding, and the tables—.

`className` is for the variants that do exist: the log viewer tightens its list
and the Dashboard's "Top" panel trims the air above.
*/
export function Cuerpo({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={[styles.cuerpo, className].filter(Boolean).join(' ')}>{children}</div>
}
