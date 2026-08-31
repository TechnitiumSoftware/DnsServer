import { Icono } from './Icono'
import styles from './Pagination.module.css'
import type { Paginacion as Ventana } from '../lib/paginacion'

/*
La barra de páginas: primera, anterior, la ventana de diez, siguiente y última.

Estaba escrita a mano en tres pantallas —la lista de zonas, los registros de una
zona y Query Logs— con el mismo marcado y la misma ristra de botones. La
aritmética ya vivía en un sitio (`lib/paginacion.ts`, que se prueba
sola); lo que faltaba era que los botones también.

Lo único que de verdad cambiaba entre las tres es CÓMO se pide la última página:
la lista de zonas y Query Logs mandan `-1` y deja que la resuelva el servidor
—es lo que hace upstream—, y los registros de una zona la calculan en el
cliente porque los tiene todos. Por eso `ultima` es un parámetro y no está
metido a fuego.
*/
export function Paginacion({
  ventana,
  actual,
  ultima,
  onIr,
}: {
  ventana: Ventana
  actual: number
  /** Qué número pedir para «última». `-1` deja que lo resuelva el servidor. */
  ultima: number
  onIr: (pagina: number) => void
}) {
  return (
    <span className={styles.pg}>
      {ventana.primera && (
        <button type="button" className={styles.pgb} aria-label="First" onClick={() => onIr(1)}>
          <Icono nombre="primera" tam={14} />
        </button>
      )}
      {ventana.anterior != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Previous"
          onClick={() => onIr(ventana.anterior!)}
        >
          <Icono nombre="chevronIzquierda" tam={14} />
        </button>
      )}
      {ventana.paginas.map((p) => (
        <button
          key={p}
          type="button"
          className={styles.pgb}
          aria-current={p === actual}
          onClick={() => onIr(p)}
        >
          {p}
        </button>
      ))}
      {ventana.siguiente != null && (
        <button
          type="button"
          className={styles.pgb}
          aria-label="Next"
          onClick={() => onIr(ventana.siguiente!)}
        >
          <Icono nombre="chevronDerecha" tam={14} />
        </button>
      )}
      {ventana.ultima && (
        <button type="button" className={styles.pgb} aria-label="Last" onClick={() => onIr(ultima)}>
          <Icono nombre="ultima" tam={14} />
        </button>
      )}
    </span>
  )
}
