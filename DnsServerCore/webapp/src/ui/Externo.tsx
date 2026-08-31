import type { ReactNode } from 'react'
import styles from './Externo.module.css'

/*
Los enlaces que salen de la consola.

Están aquí y no repartidos porque una revisión encontró que se habían ido
perdiendo de uno en uno: quedaba la frase de upstream y desaparecía el destino
—«read the change log» sin change log, «Use ZONEMD to Validate Zone» sin el
RFC—. Con un solo sitio donde se escriben, `dev/check-paridad-controles.mjs`
puede comprobar por lista que no falta ninguno.

Dos formas, que es lo que hay en upstream:

- `Externo`, dentro de una frase: «validated using the [ZONEMD] record».
- `Ayuda`, el renglón suelto al pie de un panel o un diálogo: «Help: …».
*/
export function Externo({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer">
      {children}
    </a>
  )
}

/**
 * El renglón de ayuda. No es un enlace dentro de una frase, así que no le vale
 * la excepción de tamaño de objetivo de WCAG: lleva caja propia.
 */
export function Ayuda({ href, children }: { href: string; children: ReactNode }) {
  return (
    <div className={styles.ayuda}>
      <Externo href={href}>{children}</Externo>
    </div>
  )
}
