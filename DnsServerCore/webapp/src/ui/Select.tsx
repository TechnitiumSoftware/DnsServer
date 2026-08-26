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
El desplegable, hecho aquí.

Antes era el `<select>` del sistema operativo con un chevron pintado encima: la
caja cerrada casi colaba, pero al abrirlo salía la lista del sistema —fuente,
tamaño, colores y esquinas del SO— y la consola cambiaba de aspecto según la
máquina. Y por eso «se veía muy igual»: la mitad del control no era nuestra.

Se reconstruye como listbox con las reglas de la especificación ARIA:

  · el disparador es `combobox`, con `aria-expanded` y `aria-activedescendant`
  · la lista es `listbox` y cada línea `option` con `aria-selected`
  · teclado completo: ↑ ↓ Inicio Fin, Enter y Espacio abren y eligen, Esc cierra
    devolviendo el foco, y escribir salta a la opción que empieza por ahí
  · el foco no se mueve a la lista, así que el lector de pantalla sigue
    anunciando el campo y su etiqueta

La lista va en `position: fixed` calculada desde el disparador, no absoluta: si
no, dentro de un modal —que tiene `overflow: auto`— quedaría recortada. Por lo
mismo se cierra al hacer scroll, que es lo que hace el `select` nativo.
*/

export interface Opcion {
  value: string
  label: string
  disabled?: boolean
}

const ALTO_MAX = 280

/*
Las opciones se leen de los hijos `<option>`, como en el elemento que sustituye.
Se podría haber pedido un array y obligar a reescribir los veinticinco sitios
que lo usan, pero entonces el cambio dejaría de ser sólo de diseño: cada uno de
esos sitios es una lista con su lógica —claves TSIG, catálogos, tipos de
registro, algoritmos DNSSEC— y reescribirla es una oportunidad de romperla.
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
  /** La misma firma que el elemento nativo, para no tocar quien ya lo usa. */
  onChange?: (e: { target: { value: string } }) => void
  disabled?: boolean
  /** Qué poner cuando el valor no está entre las opciones. */
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

  // La caja se mide justo antes de pintar, para que no dé un salto visible.
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
    // `true` para enterarse también del scroll de un contenedor, no sólo del de
    // la página: dentro de un modal el que rueda es el modal.
    window.addEventListener('scroll', alRodar, true)
    window.addEventListener('resize', alRodar)
    return () => {
      document.removeEventListener('mousedown', fuera)
      window.removeEventListener('scroll', alRodar, true)
      window.removeEventListener('resize', alRodar)
    }
  }, [abierto])

  // La opción marcada se mantiene a la vista al moverse con el teclado.
  useEffect(() => {
    if (!abierto) return
    const marcada = lista.current?.querySelector('[data-activa="true"]')
    // `scrollIntoView` no existe en jsdom, y tampoco pasa nada si no está.
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

    // Escribir salta a la opción que empieza por lo tecleado, como el nativo.
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
        <span className={elegida ? styles.valor : styles.vacio}>
          {elegida?.label ?? placeholder ?? ''}
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

/** El siguiente índice utilizable en esa dirección; si no hay, se queda donde está. */
function primeraUtil(opciones: Opcion[], desde: number, paso: number, actual = desde): number {
  for (let i = desde; i >= 0 && i < opciones.length; i += paso) {
    if (!opciones[i].disabled) return i
  }
  return actual
}

/** Une la referencia interna con la que pueda pasar quien usa el componente. */
function fusionar(propia: React.RefObject<HTMLButtonElement | null>, fuera?: Ref<HTMLButtonElement>) {
  return (nodo: HTMLButtonElement | null) => {
    propia.current = nodo
    if (typeof fuera === 'function') fuera(nodo)
    else if (fuera != null) (fuera as { current: HTMLButtonElement | null }).current = nodo
  }
}
