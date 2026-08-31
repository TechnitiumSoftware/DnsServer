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
import { Icon } from './Icon'
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

const MAX_HEIGHT = 280

/*
The options are read from the `<option>` children, as in the element it replaces.
It could have taken an array and forced a rewrite of the twenty-five places that
use it, but then the change would stop being design-only: each of those places is
a list with its own logic —TSIG keys, catalogs, record types, DNSSEC algorithms—
and rewriting it is an opportunity to break it.
*/
function optionsFromChildren(children: ReactNode): Option[] {
  const outside: Option[] = []
  for (const child of Children.toArray(children)) {
    if (!isValidElement(child) || child.type !== 'option') continue
    const p = child.props as { value?: string | number; children?: ReactNode; disabled?: boolean }
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
  const options = optionsFromChildren(children)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [box, setBox] = useState<{ left: number; top: number; width: number; up: boolean } | null>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const keys2 = useRef({ text: '', until: 0 })
  const listId = useId()

  const selectedIndex = options.findIndex((o) => o.value === String(value))
  const chosen = selectedIndex >= 0 ? options[selectedIndex] : undefined

  function openList() {
    if (disabled) return
    setActive(selectedIndex >= 0 ? selectedIndex : firstUsable(options, 0, 1))
    setOpen(true)
  }

  function close(returnFocus = true) {
    setOpen(false)
    if (returnFocus) trigger.current?.focus()
  }

  function choose(i: number) {
    const o = options[i]
    if (o == null || o.disabled) return
    onChange?.({ target: { value: o.value } })
    close()
  }

  // The box is measured right before painting, so it does not visibly jump.
  useLayoutEffect(() => {
    if (!open) { setBox(null); return }
    const r = trigger.current?.getBoundingClientRect()
    if (r == null) return
    const below = window.innerHeight - r.bottom
    const up = below < Math.min(MAX_HEIGHT, options.length * 30 + 8) && r.top > below
    setBox({ left: r.left, top: up ? r.top : r.bottom, width: r.width, up })
  }, [open, options.length])

  useEffect(() => {
    if (!open) return
    const outside = (e: MouseEvent) => {
      const t = e.target as Node
      if (!trigger.current?.contains(t) && !list.current?.contains(t)) setOpen(false)
    }
    const onScroll = () => setOpen(false)
    document.addEventListener('mousedown', outside)
    // `true` so it also hears a container's scroll, not only the page's:
    // inside a modal the thing that scrolls is the modal.
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', onScroll)
    return () => {
      document.removeEventListener('mousedown', outside)
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', onScroll)
    }
  }, [open])

  // The selected option is kept in view when moving with the keyboard.
  useEffect(() => {
    if (!open) return
    const checked = list.current?.querySelector('[data-activa="true"]')
    // `scrollIntoView` does not exist in jsdom, and nothing breaks without it.
    checked?.scrollIntoView?.({ block: 'nearest' })
  }, [open, active])

  function onKeyDown(e: React.KeyboardEvent) {
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
        setOpen(false)
        return
      case 'Enter':
      case ' ':
        e.preventDefault()
        choose(active)
        return
      case 'ArrowDown':
        e.preventDefault()
        setActive((i) => firstUsable(options, i + 1, 1, i))
        return
      case 'ArrowUp':
        e.preventDefault()
        setActive((i) => firstUsable(options, i - 1, -1, i))
        return
      case 'Home':
        e.preventDefault()
        setActive(firstUsable(options, 0, 1))
        return
      case 'End':
        e.preventDefault()
        setActive(firstUsable(options, options.length - 1, -1))
        return
      default:
        break
    }

    // Typing jumps to the option starting with what was typed, like the native one.
    if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const now = Date.now()
      keys2.current.text = now > keys2.current.until ? e.key : keys2.current.text + e.key
      keys2.current.until = now + 600
      const wanted = keys2.current.text.toLowerCase()
      const i = options.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(wanted))
      if (i >= 0) setActive(i)
    }
  }

  return (
    <>
      <button
        type="button"
        id={id}
        ref={merge(trigger, ref)}
        role="combobox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={open ? `${listId}-${active}` : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        className={[styles.trigger, className].filter(Boolean).join(' ')}
        onClick={() => (open ? close(false) : openList())}
        onKeyDown={onKeyDown}
      >
        {/*
        An option with no label —a filter's "any"— is drawn with a dash, just as
        it is inside the list. Completely empty, the control reads as a broken box
        rather than as "nothing is selected".
        */}
        <span className={chosen?.label ? styles.value : styles.emptyText}>
          {chosen?.label || placeholder || '—'}
        </span>
        <Icon name="chevronDown" size={14} className={styles.chevron} />
      </button>

      {open && box && (
        <div
          ref={list}
          id={listId}
          role="listbox"
          className={styles.list}
          style={{
            left: box.left,
            width: box.width,
            maxHeight: MAX_HEIGHT,
            ...(box.up
              ? { bottom: window.innerHeight - box.top + 4 }
              : { top: box.top + 4 }),
          }}
        >
          {options.map((o, i) => (
            <div
              key={o.value}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={o.value === String(value)}
              aria-disabled={o.disabled}
              data-active={i === active}
              className={styles.option}
              onMouseEnter={() => !o.disabled && setActive(i)}
              onClick={() => choose(i)}
            >
              <span className={styles.brand}>
                {o.value === String(value) && <Icon name="check" size={13} />}
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
function firstUsable(options: Option[], since2: number, step: number, current = since2): number {
  for (let i = since2; i >= 0 && i < options.length; i += step) {
    if (!options[i].disabled) return i
  }
  return current
}

/** Merges the internal ref with whatever the caller may pass. */
function merge(own: React.RefObject<HTMLButtonElement | null>, outside?: Ref<HTMLButtonElement>) {
  return (node: HTMLButtonElement | null) => {
    own.current = node
    if (typeof outside === 'function') outside(node)
    else if (outside != null) (outside as { current: HTMLButtonElement | null }).current = node
  }
}
