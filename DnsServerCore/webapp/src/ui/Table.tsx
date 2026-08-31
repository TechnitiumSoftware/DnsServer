import { useState, type ReactNode } from 'react'
import { Button } from './Button'
import { Icono, type NombreIcono } from './Icono'
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
export function Tabla({
  cabecera,
  children,
  vacia = false,
  vacio,
  columnas,
  className,
  claseTabla,
  pie,
}: {
  /** The `thead` cells; normally `Th` from this same module. */
  cabecera: ReactNode
  children: ReactNode
  /** Si no hay filas que pintar. */
  vacia?: boolean
  /** What to say then. Without this, an empty table shows a blank body. */
  vacio?: ReactNode
  /** How many columns that row spans. */
  columnas?: number
  /** For the wrapper: the max width of a narrow table, for example. */
  className?: string
  /** For the table: the sticky header of the "More" dialog, for example. */
  claseTabla?: string
  /** La fila de pie, cuando la tabla lleva su recuento dentro. */
  pie?: ReactNode
}) {
  return (
    <div className={[styles.wrap, className].filter(Boolean).join(' ')}>
      <table className={[styles.tabla, claseTabla].filter(Boolean).join(' ')}>
        <thead>
          <tr>{cabecera}</tr>
        </thead>
        <tbody>
          {vacia && vacio != null ? (
            <tr>
              <td colSpan={columnas} className={styles.sinFilas}>
                {vacio}
              </td>
            </tr>
          ) : (
            children
          )}
        </tbody>
        {pie != null && (
          <tfoot>
            <tr>{pie}</tr>
          </tfoot>
        )}
      </table>
    </div>
  )
}

export interface Orden {
  campo: string
  desc: boolean
}

/** How each sortable column is read: the text the user sees in the cell. */
export type Claves<T> = Record<string, (fila: T) => string | number | null | undefined>

function texto(v: string | number | null | undefined): string {
  return String(v ?? '').toLowerCase()
}

export function useOrden<T>(claves: Claves<T>, filas: T[]) {
  const [orden, setOrden] = useState<Orden | null>(null)

  const ordenadas = (() => {
    if (orden == null || claves[orden.campo] == null) return filas
    const leer = claves[orden.campo]
    const signo = orden.desc ? -1 : 1
    return [...filas].sort((a, b) => {
      const x = texto(leer(a))
      const y = texto(leer(b))
      return x === y ? 0 : (x > y ? 1 : -1) * signo
    })
  })()

  function alternar(campo: string) {
    const leer = claves[campo]
    if (leer == null) return
    // Se mira la lista TAL COMO ESTÁ PINTADA, que es lo que mira upstream.
    const yaAsc = ordenadas.every((f, i) => i === 0 || texto(leer(ordenadas[i - 1])) <= texto(leer(f)))
    setOrden({ campo, desc: yaAsc })
  }

  return { filas: ordenadas, orden, alternar }
}

/** Cabecera de columna ordenable. Sin `campo` es una cabecera normal. */
export function Th({
  campo,
  orden,
  onOrdenar,
  children,
  nombre,
  ...rest
}: {
  campo?: string
  orden?: Orden | null
  onOrdenar?: (campo: string) => void
  children?: ReactNode
  /** For a header upstream leaves BLANK and which is still sortable: the button
   *  needs a name even though the cell shows no label. */
  nombre?: string
} & React.ThHTMLAttributes<HTMLTableCellElement>) {
  if (campo == null || onOrdenar == null) return <th {...rest}>{children}</th>

  const activa = orden?.campo === campo
  return (
    <th aria-sort={activa ? (orden!.desc ? 'descending' : 'ascending') : 'none'} {...rest}>
      <button
        type="button"
        className={styles.orden}
        aria-label={children == null ? nombre : undefined}
        onClick={() => onOrdenar(campo)}
      >
        {children}
        <span className={styles.flecha}>
          <Icono nombre={activa ? 'chevronAbajo' : 'orden'} tam={12} data-desc={activa && !orden!.desc} />
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
export function AccionFila({
  icono,
  nombre,
  ...rest
}: {
  icono: NombreIcono
  /** What it does, in upstream's wording: "Options", "Disable", "Edit". */
  nombre: string
} & Omit<React.ComponentProps<typeof Button>, 'children' | 'size' | 'icono'>) {
  return (
    <Button size="sm" icono aria-label={nombre} title={nombre} {...rest}>
      <Icono nombre={icono} tam={15} />
    </Button>
  )
}
