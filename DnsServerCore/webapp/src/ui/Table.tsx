import { useState, type ReactNode } from 'react'
import { Button } from './Button'
import { Icon, type IconName } from './Icon'
import styles from './Table.module.css'

/*
Sorting by column. Upstream has it on thirteen tables (`sortTable`,
common.js:228-280) and the new console had lost it entirely: with 240 zones
paginated ten at a time, "which ones do I still have to sign" could not be
answered.

Its rule is replicated, and it is not a plain toggle:

  · A click sorts ASCENDING…
  · …unless the column is already ascending, in which case it sorts DESCENDING.

That is what its bubble sort does: it starts at `asc` and, if the first pass
swaps nothing, it turns around. For a user clicking twice in a row the effect is
the same as a switch; the difference is in the FIRST click on a column that was
already sorted, and there we match too.

And it sorts by the TEXT YOU SEE, lowercased and compared by character code, just
like upstream: that way a column of `2026-08-26 10:48` dates comes out right
without treating it as a date, and the order is the same the old console gave.
*/

/*
The table: the scaffolding, not just the styles.

This module exported `useOrden`, `Th` and `AccionFila` —the helpers— and let each
screen write the wrapper, the `table`, the `thead` and the `tbody` by hand.
Eighteen tables with the same structure typed out eighteen times, and everything
copying allows: six of the seven data tables had been left without their "there
is nothing here" row, and the "My Profile" one ended up with a cell density of
its own because nobody tied it to the shared one.

What is shared now is the PIECE. What still belongs to each screen is the only
thing that really changes: which columns there are and what goes in each row.

    <Tabla
      cabecera={<><Th …>Username</Th>…</>}
      vacia={usuarios.length === 0}
      vacio="No User Found"
      columnas={8}
    >
      {usuarios.map((u) => <tr key={u.username}>…</tr>)}
    </Tabla>

`vacia` is explicit and not guessed by counting children: a `.map()` over an empty
list hands back an empty array, not zero children, and a detection that is right
by accident is worse than a parameter.
*/
export function Table({
  header,
  children,
  isEmpty = false,
  emptyText,
  columns,
  className,
  tableClass,
  footer,
}: {
  /** The `thead` cells; normally `Th` from this same module. */
  header: ReactNode
  children: ReactNode
  /** Whether there are no rows to draw. */
  isEmpty?: boolean
  /** What to say then. Without this, an empty table shows a blank body. */
  emptyText?: ReactNode
  /** How many columns that row spans. */
  columns?: number
  /** For the wrapper: the max width of a narrow table, for example. */
  className?: string
  /** For the table: the sticky header of the "More" dialog, for example. */
  tableClass?: string
  /** The footer row, when the table carries its count inside. */
  footer?: ReactNode
}) {
  return (
    <div className={[styles.wrap, className].filter(Boolean).join(' ')}>
      <table className={[styles.table, tableClass].filter(Boolean).join(' ')}>
        <thead>
          <tr>{header}</tr>
        </thead>
        <tbody>
          {isEmpty && emptyText != null ? (
            <tr>
              <td colSpan={columns} className={styles.noRows}>
                {emptyText}
              </td>
            </tr>
          ) : (
            children
          )}
        </tbody>
        {footer != null && (
          <tfoot>
            <tr>{footer}</tr>
          </tfoot>
        )}
      </table>
    </div>
  )
}

export interface Sort {
  field: string
  desc: boolean
}

/** How each sortable column is read: the text the user sees in the cell. */
export type Keys<T> = Record<string, (row: T) => string | number | null | undefined>

function text(v: string | number | null | undefined): string {
  return String(v ?? '').toLowerCase()
}

export function useOrden<T>(keys: Keys<T>, rows: T[]) {
  const [sort, setOrden] = useState<Sort | null>(null)

  const sorted = (() => {
    if (sort == null || keys[sort.field] == null) return rows
    const read = keys[sort.field]
    const signo = sort.desc ? -1 : 1
    return [...rows].sort((a, b) => {
      const x = text(read(a))
      const y = text(read(b))
      return x === y ? 0 : (x > y ? 1 : -1) * signo
    })
  })()

  function toggle(field: string) {
    const read = keys[field]
    if (read == null) return
    // The list is looked at AS IT IS DRAWN, which is what upstream looks at.
    const yaAsc = sorted.every((f, i) => i === 0 || text(read(sorted[i - 1])) <= text(read(f)))
    setOrden({ field, desc: yaAsc })
  }

  return { rows: sorted, sort, toggle }
}

/** A sortable column header. Without `campo` it is an ordinary header. */
export function Th({
  field,
  sort,
  onSort,
  children,
  name,
  ...rest
}: {
  field?: string
  sort?: Sort | null
  onSort?: (field: string) => void
  children?: ReactNode
  /** For a header upstream leaves BLANK and which is still sortable: the button
   *  needs a name even though the cell shows no label. */
  name?: string
} & React.ThHTMLAttributes<HTMLTableCellElement>) {
  if (field == null || onSort == null) return <th {...rest}>{children}</th>

  const active = sort?.field === field
  return (
    <th aria-sort={active ? (sort!.desc ? 'descending' : 'ascending') : 'none'} {...rest}>
      <button
        type="button"
        className={styles.sort}
        aria-label={children == null ? name : undefined}
        onClick={() => onSort(field)}
      >
        {children}
        <span className={styles.flecha}>
          <Icon name={active ? 'chevronDown' : 'sort'} tam={12} data-desc={active && !sort!.desc} />
        </span>
      </button>
    </th>
  )
}

/*
The button for a row action. It carries an icon and not a label —see the measured
reasoning in `Table.module.css`— but keeps its name in `aria-label` and in
`title`, so the keyboard, the screen reader and the tooltip all say the same thing
the text that used to fill the column said.
*/
export function RowAction({
  icon,
  name,
  ...rest
}: {
  icon: IconName
  /** What it does, in upstream's wording: "Options", "Disable", "Edit". */
  name: string
} & Omit<React.ComponentProps<typeof Button>, 'children' | 'size' | 'icon'>) {
  return (
    <Button size="sm" icon aria-label={name} title={name} {...rest}>
      <Icon name={icon} tam={15} />
    </Button>
  )
}
