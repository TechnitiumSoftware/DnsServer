import {
  Children,
  isValidElement,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react'
import { Icon } from './Icono'
import styles from './Select.module.css'

/*
The dropdown, built here.

It used to be the operating system's `<select>` with a chevron painted on top:
the closed box almost passed, but on opening it the system list appeared —the
OS's font, size, colours and corners— and the console changed appearance
depending on the machine. And that is why it "looked very much the same": half
the control was not ours.

It is rebuilt as a listbox following the ARIA specification's rules:

  · the trigger is a `combobox`, with `aria-expanded` and `aria-activedescendant`
  · the list is a `listbox` and each line an `option` with `aria-selected`
  · full keyboard: ↑ ↓ Home End, Enter and Space open and choose, Esc closes and
    returns focus, and typing jumps to the option starting with it
  · focus does not move into the list, so the screen reader keeps announcing the
    field and its label

The list is `position: fixed` computed from the trigger, not absolute: otherwise,
inside a modal —which has `overflow: auto`— it would be clipped. For the same
reason it closes on scroll, which is what the native `select` does.
*/

export interface Option {
  value: string
  label: string
  disabled?: boolean
}

const ALTO_MAX = 280

/*
The options are read from the `<option>` children, as in the element it replaces.
It could have taken an array and forced a rewrite of the twenty-five places that
use it, but then the change would stop being design-only: each of those places is
a list with its own logic —TSIG keys, catalogs, record types, DNSSEC algorithms—
and rewriting it is an opportunity to break it.
*/
function opcionesDeHijos(children: ReactNode): Option[] {
  const outside: Option[] = []
  for (const hijo of Children.toArray(children)) {
    if (!isValidElement(hijo) || hijo.type !== 'option') continue
    const p = hijo.props as { value?: string | number; children?: ReactNode; disabled?: boolean }
    const text = typeof p.children === 'string' || typeof p.children === 'number' ? String(p.children) : ''
    outside.push({
      value: p.value != null ? String(p.value) : text,
      label: text,
      disabled: p.disabled,
    })
  }
  return outside
}

export function Select({
  id,
  value,
  children,
  onChange,
  disabled = false,
  placeholder,
  className,
  ref,
  'aria-label': ariaLabel,
}: {
  id?: string
  value: string | number
  children?: ReactNode
  /** The same signature as the native element, so existing callers are untouched. */
  onChange?: (e: { target: { value: string } }) => void
  disabled?: boolean
  /** What to show when the value is not among the options. */
  placeholder?: string
  className?: string
  ref?: Ref<HTMLButtonElement>
  'aria-label'?: string
}) {
  const options = opcionesDeHijos(children)
  const [open, setAbierto] = useState(false)
  const [active, setActivo] = useState(0)
  const [caja, setCaja] = useState<{ left: number; top: number; width: number; up: boolean } | null>(null)
  const disparador = useRef<HTMLButtonElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const teclas = useRef({ text: '', hasta: 0 })
  const idLista = useId()

  const indiceSel = options.findIndex((o) => o.value === String(value))
  const elegida = indiceSel >= 0 ? options[indiceSel] : undefined

  function openList() {
    if (disabled) return
    setActivo(indiceSel >= 0 ? indiceSel : primeraUtil(options, 0, 1))
    setAbierto(true)
  }

  function close(devolverFoco = true) {
    setAbierto(false)
    if (devolverFoco) disparador.current?.focus()
  }

  function choose(i: number) {
    const o = options[i]
    if (o == null || o.disabled) return
    onChange?.({ target: { value: o.value } })
    close()
  }

  // The box is measured right before painting, so it does not visibly jump.
  useLayoutEffect(() => {
    if (!open) { setCaja(null); return }
    const r = disparador.current?.getBoundingClientRect()
    if (r == null) return
    const debajo = window.innerHeight - r.bottom
    const up = debajo < Math.min(ALTO_MAX, options.length * 30 + 8) && r.top > debajo
    setCaja({ left: r.left, top: up ? r.top : r.bottom, width: r.width, up })
  }, [open, options.length])

  useEffect(() => {
    if (!open) return
    const outside = (e: MouseEvent) => {
      const t = e.target as Node
      if (!disparador.current?.contains(t) && !list.current?.contains(t)) setAbierto(false)
    }
    const alRodar = () => setAbierto(false)
    document.addEventListener('mousedown', outside)
    // `true` so it also hears a container's scroll, not only the page's:
    // inside a modal the thing that scrolls is the modal.
    window.addEventListener('scroll', alRodar, true)
    window.addEventListener('resize', alRodar)
    return () => {
      document.removeEventListener('mousedown', outside)
      window.removeEventListener('scroll', alRodar, true)
      window.removeEventListener('resize', alRodar)
    }
  }, [open])

  // The selected option is kept in view when moving with the keyboard.
  useEffect(() => {
    if (!open) return
    const checked = list.current?.querySelector('[data-activa="true"]')
    // `scrollIntoView` does not exist in jsdom, and nothing breaks without it.
    checked?.scrollIntoView?.({ block: 'nearest' })
  }, [open, active])

  function alTeclado(e: React.KeyboardEvent) {
    if (disabled) return

    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        openList()
      }
      return
    }

    switch (e.key) {
      case 'Escape':
        e.preventDefault()
        close()
        return
      case 'Tab':
        setAbierto(false)
        return
      case 'Enter':
      case ' ':
        e.preventDefault()
        choose(active)
        return
      case 'ArrowDown':
        e.preventDefault()
        setActivo((i) => primeraUtil(options, i + 1, 1, i))
        return
      case 'ArrowUp':
        e.preventDefault()
        setActivo((i) => primeraUtil(options, i - 1, -1, i))
        return
      case 'Home':
        e.preventDefault()
        setActivo(primeraUtil(options, 0, 1))
        return
      case 'End':
        e.preventDefault()
        setActivo(primeraUtil(options, options.length - 1, -1))
        return
      default:
        break
    }

    // Typing jumps to the option starting with what was typed, like the native one.
    if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const ahora = Date.now()
      teclas.current.text = ahora > teclas.current.hasta ? e.key : teclas.current.text + e.key
      teclas.current.hasta = ahora + 600
      const wanted = teclas.current.text.toLowerCase()
      const i = options.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(wanted))
      if (i >= 0) setActivo(i)
    }
  }

  return (
    <>
      <button
        type="button"
        id={id}
        ref={fusionar(disparador, ref)}
        role="combobox"
        aria-expanded={open}
        aria-controls={open ? idLista : undefined}
        aria-activedescendant={open ? `${idLista}-${active}` : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        className={[styles.disparador, className].filter(Boolean).join(' ')}
        onClick={() => (open ? close(false) : openList())}
        onKeyDown={alTeclado}
      >
        {/*
        An option with no label —a filter's "any"— is drawn with a dash, just as
        it is inside the list. Completely empty, the control reads as a broken box
        rather than as "nothing is selected".
        */}
        <span className={elegida?.label ? styles.value : styles.emptyText}>
          {elegida?.label || placeholder || '—'}
        </span>
        <Icon name="chevronDown" tam={14} className={styles.chevron} />
      </button>

      {open && caja && (
        <div
          ref={list}
          id={idLista}
          role="listbox"
          className={styles.list}
          style={{
            left: caja.left,
            width: caja.width,
            maxHeight: ALTO_MAX,
            ...(caja.up
              ? { bottom: window.innerHeight - caja.top + 4 }
              : { top: caja.top + 4 }),
          }}
        >
          {options.map((o, i) => (
            <div
              key={o.value}
              id={`${idLista}-${i}`}
              role="option"
              aria-selected={o.value === String(value)}
              aria-disabled={o.disabled}
              data-active={i === active}
              className={styles.option}
              onMouseEnter={() => !o.disabled && setActivo(i)}
              onClick={() => choose(i)}
            >
              <span className={styles.brand}>
                {o.value === String(value) && <Icon name="check" tam={13} />}
              </span>
              {o.label === '' ? <span className={styles.isEmpty}>—</span> : o.label}
            </div>
          ))}
        </div>
      )}
    </>
  )
}

/** The next usable index in that direction; if there is none, it stays put. */
function primeraUtil(options: Option[], desde: number, step: number, current = desde): number {
  for (let i = desde; i >= 0 && i < options.length; i += step) {
    if (!options[i].disabled) return i
  }
  return current
}

/** Merges the internal ref with whatever the caller may pass. */
function fusionar(own: React.RefObject<HTMLButtonElement | null>, outside?: Ref<HTMLButtonElement>) {
  return (node: HTMLButtonElement | null) => {
    own.current = node
    if (typeof outside === 'function') outside(node)
    else if (outside != null) (outside as { current: HTMLButtonElement | null }).current = node
  }
}
