import { Button } from './Button'
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import styles from './Menu.module.css'
import { Icon } from './Icono'

/*
The `⋮` menu on each row. Upstream solves it with the Bootstrap 3 dropdown; here
it is a button with a list that closes on an outside click or on Escape.

It used to live inside Zones and now belongs to everyone, because the rule that
orders row actions needs it on every table: **destructive things go in here**. A
row cannot have a loose "Delete" next to a "Disable" —there are two hundred and
forty rows and this console has no undo anywhere— so deleting costs you opening
the menu. On a detail screen it does go outside: there you act on an object you
are looking at.

It deliberately does not use Radix: `DropdownMenu` would bring a new dependency
into `package.json` for a twenty-line component, and the project's primitives are
deliberately few.

And it is the ONLY menu. There was another one written by hand in the sidebar
—the account one— with its own list, its own styles and its own state, and what
it had forgotten was everything you cannot see by looking at it open: it did not
close on an outside click, nor on Escape, nor on scroll. Three behaviours already
solved here. The difference that was real —it hangs upwards from the foot of the
sidebar, aligned left, and its trigger is a wide row instead of a button— is the
two parameters below.
*/

export function Menu({
  etiqueta,
  rotulo,
  onAbrir,
  ancla = 'derecha',
  comoFila = false,
  children,
}: {
  /** Accessible name; it is all there is when it carries no visible label. */
  etiqueta: string
  /** Visible text. Without it, the button is the compact `⋮` of a row. */
  rotulo?: string
  /**
   * Fired on open, for the menu that needs to know the server state right before
   * showing its options. Upstream does the same with the Dashboard's blocking
   * menu (`main.js:2429`): it asks on open, not on render, because between the
   * two the setting may have changed in another tab.
   */
  onAbrir?: () => void
  /** Which edge the list aligns to against the trigger. */
  ancla?: 'derecha' | 'izquierda'
  /** The trigger fills the width of its column, with the label on the left. */
  comoFila?: boolean
  children: (close: () => void) => ReactNode
}) {
  const [open, setAbierto] = useState(false)
  const [caja, setCaja] = useState<
    { right?: number; left?: number; top?: number; bottom?: number; maxHeight: number } | null
  >(null)
  const disparador = useRef<HTMLButtonElement>(null)
  const list = useRef<HTMLDivElement>(null)

  /*
  The list is `position: fixed`, measured from the trigger, and NOT absolute
  inside the row. Absolute did not work: two containers clipped it at once —the
  segmented actions group, which carries `overflow: hidden` for its corners, and
  the table wrapper, which carries `overflow-x: auto`— so the menu opened and was
  not visible. It is the same reason `ui/Select` takes its list out fixed, and the
  same reason it closes on scroll.
  */
  /*
  And it opens wherever it fits. A long menu hanging off a low trigger spilled
  out the bottom: the Dashboard's blocking menu is nine options over a panel
  halfway down the screen, and the last three fell outside the window. With no way
  out, on top of that, because this menu closes on scroll.

  So if it does not fit below and there is more room above, it anchors by its
  bottom edge; and either way the available height is set as a cap, with the list
  scrolling inside. The second part is the belt: even if it fits on neither side
  —a very short window— every option is still reachable.
  */
  useLayoutEffect(() => {
    if (!open) { setCaja(null); return }
    const r = disparador.current?.getBoundingClientRect()
    if (r == null) return

    const MARGEN = 8
    const debajo = window.innerHeight - r.bottom - MARGEN
    const encima = r.top - MARGEN
    const borde = ancla === 'izquierda' ? { left: r.left } : { right: window.innerWidth - r.right }

    setCaja(
      debajo < encima && debajo < 240
        ? { ...borde, bottom: window.innerHeight - r.top + 4, maxHeight: encima }
        : { ...borde, top: r.bottom + 4, maxHeight: debajo },
    )
  }, [open, ancla])

  useEffect(() => {
    if (!open) return

    function outside(e: MouseEvent) {
      const t = e.target as Node
      if (!disparador.current?.contains(t) && !list.current?.contains(t)) setAbierto(false)
    }
    function escape(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setAbierto(false)
        disparador.current?.focus()
      }
    }
    /* Scrolling the page closes it, but scrolling the list itself does not: ever
       since the list can have a height cap, that scroll is its own.

       The `instanceof` is not redundant: this same handler serves `resize`, and
       there the `target` is `window`, which is not a node. Without the guard,
       `contains()` threw on every resize with a menu open. */
    const alRodar = (e: Event) => {
      if (e.target instanceof Node && list.current?.contains(e.target)) return
      setAbierto(false)
    }

    document.addEventListener('mousedown', outside)
    document.addEventListener('keydown', escape)
    window.addEventListener('scroll', alRodar, true)
    window.addEventListener('resize', alRodar)
    return () => {
      document.removeEventListener('mousedown', outside)
      document.removeEventListener('keydown', escape)
      window.removeEventListener('scroll', alRodar, true)
      window.removeEventListener('resize', alRodar)
    }
  }, [open])

  const toggleOpen = () => {
    if (!open) onAbrir?.()
    setAbierto((v) => !v)
  }

  return (
    <div className={comoFila ? styles.menuWidth : styles.menu}>
      {comoFila ? (
        <button
          ref={disparador}
          type="button"
          className={styles.row}
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={toggleOpen}
        >
          {rotulo}
          <Icon name="chevronDown" tam={12} />
        </button>
      ) : (
        <Button
          ref={disparador}
          size="sm"
          icon={rotulo == null}
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={etiqueta}
          onClick={toggleOpen}
        >
          {rotulo == null ? (
            <Icon name="plus" tam={16} />
          ) : (
            <>
              {rotulo}
              <Icon name="chevronDown" tam={12} />
            </>
          )}
        </Button>
      )}
      {open && caja && (
        <div className={styles.menuList} role="menu" ref={list} style={caja}>
          {children(() => setAbierto(false))}
        </div>
      )}
    </div>
  )
}

export function Separador() {
  return <div className={styles.sep} role="separator" />
}
