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
import { Icono } from './Icono'
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

export interface Opcion {
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
function opcionesDeHijos(children: ReactNode): Opcion[] {
  const fuera: Opcion[] = []
  for (const hijo of Children.toArray(children)) {
    if (!isValidElement(hijo) || hijo.type !== 'option') continue
    const p = hijo.props as { value?: string | number; children?: ReactNode; disabled?: boolean }
    const texto = typeof p.children === 'string' || typeof p.children === 'number' ? String(p.children) : ''
    fuera.push({
      value: p.value != null ? String(p.value) : texto,
      label: texto,
      disabled: p.disabled,
    })
  }
  return fuera
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
  const opciones = opcionesDeHijos(children)
  const [abierto, setAbierto] = useState(false)
  const [activo, setActivo] = useState(0)
  const [caja, setCaja] = useState<{ left: number; top: number; width: number; arriba: boolean } | null>(null)
  const disparador = useRef<HTMLButtonElement>(null)
  const lista = useRef<HTMLDivElement>(null)
  const teclas = useRef({ texto: '', hasta: 0 })
  const idLista = useId()

  const indiceSel = opciones.findIndex((o) => o.value === String(value))
  const elegida = indiceSel >= 0 ? opciones[indiceSel] : undefined

  function abrir() {
    if (disabled) return
    setActivo(indiceSel >= 0 ? indiceSel : primeraUtil(opciones, 0, 1))
    setAbierto(true)
  }

  function cerrar(devolverFoco = true) {
    setAbierto(false)
    if (devolverFoco) disparador.current?.focus()
  }

  function elegir(i: number) {
    const o = opciones[i]
    if (o == null || o.disabled) return
    onChange?.({ target: { value: o.value } })
    cerrar()
  }

  // The box is measured right before painting, so it does not visibly jump.
  useLayoutEffect(() => {
    if (!abierto) { setCaja(null); return }
    const r = disparador.current?.getBoundingClientRect()
    if (r == null) return
    const debajo = window.innerHeight - r.bottom
    const arriba = debajo < Math.min(ALTO_MAX, opciones.length * 30 + 8) && r.top > debajo
    setCaja({ left: r.left, top: arriba ? r.top : r.bottom, width: r.width, arriba })
  }, [abierto, opciones.length])

  useEffect(() => {
    if (!abierto) return
    const fuera = (e: MouseEvent) => {
      const t = e.target as Node
      if (!disparador.current?.contains(t) && !lista.current?.contains(t)) setAbierto(false)
    }
    const alRodar = () => setAbierto(false)
    document.addEventListener('mousedown', fuera)
    // `true` so it also hears a container's scroll, not only the page's:
    // inside a modal the thing that scrolls is the modal.
    window.addEventListener('scroll', alRodar, true)
    window.addEventListener('resize', alRodar)
    return () => {
      document.removeEventListener('mousedown', fuera)
      window.removeEventListener('scroll', alRodar, true)
      window.removeEventListener('resize', alRodar)
    }
  }, [abierto])

  // The selected option is kept in view when moving with the keyboard.
  useEffect(() => {
    if (!abierto) return
    const marcada = lista.current?.querySelector('[data-activa="true"]')
    // `scrollIntoView` does not exist in jsdom, and nothing breaks without it.
    marcada?.scrollIntoView?.({ block: 'nearest' })
  }, [abierto, activo])

  function alTeclado(e: React.KeyboardEvent) {
    if (disabled) return

    if (!abierto) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        abrir()
      }
      return
    }

    switch (e.key) {
      case 'Escape':
        e.preventDefault()
        cerrar()
        return
      case 'Tab':
        setAbierto(false)
        return
      case 'Enter':
      case ' ':
        e.preventDefault()
        elegir(activo)
        return
      case 'ArrowDown':
        e.preventDefault()
        setActivo((i) => primeraUtil(opciones, i + 1, 1, i))
        return
      case 'ArrowUp':
        e.preventDefault()
        setActivo((i) => primeraUtil(opciones, i - 1, -1, i))
        return
      case 'Home':
        e.preventDefault()
        setActivo(primeraUtil(opciones, 0, 1))
        return
      case 'End':
        e.preventDefault()
        setActivo(primeraUtil(opciones, opciones.length - 1, -1))
        return
      default:
        break
    }

    // Typing jumps to the option starting with what was typed, like the native one.
    if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const ahora = Date.now()
      teclas.current.texto = ahora > teclas.current.hasta ? e.key : teclas.current.texto + e.key
      teclas.current.hasta = ahora + 600
      const buscado = teclas.current.texto.toLowerCase()
      const i = opciones.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(buscado))
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
        aria-expanded={abierto}
        aria-controls={abierto ? idLista : undefined}
        aria-activedescendant={abierto ? `${idLista}-${activo}` : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        className={[styles.disparador, className].filter(Boolean).join(' ')}
        onClick={() => (abierto ? cerrar(false) : abrir())}
        onKeyDown={alTeclado}
      >
        {/*
        An option with no label —a filter's "any"— is drawn with a dash, just as
        it is inside the list. Completely empty, the control reads as a broken box
        rather than as "nothing is selected".
        */}
        <span className={elegida?.label ? styles.valor : styles.vacio}>
          {elegida?.label || placeholder || '—'}
        </span>
        <Icono nombre="chevronAbajo" tam={14} className={styles.chevron} />
      </button>

      {abierto && caja && (
        <div
          ref={lista}
          id={idLista}
          role="listbox"
          className={styles.lista}
          style={{
            left: caja.left,
            width: caja.width,
            maxHeight: ALTO_MAX,
            ...(caja.arriba
              ? { bottom: window.innerHeight - caja.top + 4 }
              : { top: caja.top + 4 }),
          }}
        >
          {opciones.map((o, i) => (
            <div
              key={o.value}
              id={`${idLista}-${i}`}
              role="option"
              aria-selected={o.value === String(value)}
              aria-disabled={o.disabled}
              data-activa={i === activo}
              className={styles.opcion}
              onMouseEnter={() => !o.disabled && setActivo(i)}
              onClick={() => elegir(i)}
            >
              <span className={styles.marca}>
                {o.value === String(value) && <Icono nombre="check" tam={13} />}
              </span>
              {o.label === '' ? <span className={styles.vacia}>—</span> : o.label}
            </div>
          ))}
        </div>
      )}
    </>
  )
}

/** The next usable index in that direction; if there is none, it stays put. */
function primeraUtil(opciones: Opcion[], desde: number, paso: number, actual = desde): number {
  for (let i = desde; i >= 0 && i < opciones.length; i += paso) {
    if (!opciones[i].disabled) return i
  }
  return actual
}

/** Merges the internal ref with whatever the caller may pass. */
function fusionar(propia: React.RefObject<HTMLButtonElement | null>, fuera?: Ref<HTMLButtonElement>) {
  return (nodo: HTMLButtonElement | null) => {
    propia.current = nodo
    if (typeof fuera === 'function') fuera(nodo)
    else if (fuera != null) (fuera as { current: HTMLButtonElement | null }).current = nodo
  }
}
