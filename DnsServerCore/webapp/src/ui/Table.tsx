import { useState, type ReactNode } from 'react'
import { Button } from './Button'
import { Icono, type NombreIcono } from './Icono'
import styles from './Table.module.css'

/*
Ordenación por columna. Upstream la tiene en trece tablas (`sortTable`,
common.js:228-280) y la consola nueva la había perdido entera: con 240 zonas
paginadas de diez en diez, «cuáles me faltan por firmar» no se podía contestar.

Se replica su regla, que no es un simple ida y vuelta:

  · La pulsación ordena ASCENDENTE…
  · …salvo que la columna ya esté ascendente, y entonces ordena DESCENDENTE.

Es lo que hace su burbuja: arranca en `asc` y, si la primera pasada no
intercambia nada, se da la vuelta. Para el usuario que pulsa dos veces seguidas
el efecto es el mismo que un interruptor; la diferencia está en la PRIMERA
pulsación sobre una columna que ya venía ordenada, y ahí también coincidimos.

Y se ordena por el TEXTO QUE SE VE, en minúsculas y comparando por código de
carácter, igual que upstream: así una columna de fechas `2026-08-26 10:48` sale
bien sin tratarla como fecha, y el orden es el mismo que daba la consola vieja.
*/

export interface Orden {
  campo: string
  desc: boolean
}

/** Cómo se lee cada columna ordenable: el texto que el usuario ve en la celda. */
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
  /** Para una cabecera que upstream deja EN BLANCO y aun así se puede ordenar:
   *  el botón necesita nombre aunque la celda no enseñe rótulo. */
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
El botón de una acción de fila. Lleva icono y no rótulo —ver el porqué medido en
`Table.module.css`— pero conserva su nombre en `aria-label` y en `title`, así que
el teclado, el lector de pantalla y el globo de ayuda dicen lo mismo que decía el
texto que ocupaba la columna.
*/
export function AccionFila({
  icono,
  nombre,
  ...rest
}: {
  icono: NombreIcono
  /** Lo que hace, en el idioma de upstream: «Options», «Disable», «Edit». */
  nombre: string
} & Omit<React.ComponentProps<typeof Button>, 'children' | 'size' | 'icono'>) {
  return (
    <Button size="sm" icono aria-label={nombre} title={nombre} {...rest}>
      <Icono nombre={icono} tam={15} />
    </Button>
  )
}
