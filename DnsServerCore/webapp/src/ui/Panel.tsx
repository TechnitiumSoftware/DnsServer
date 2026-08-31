import { useId, type ReactNode } from 'react'
import styles from './Panel.module.css'

/*
La caja con borde de la consola: UN componente, no una clase que cada pantalla
se aplica por su cuenta.

Antes esto era `<fieldset>` con un `<legend>` de cabecera, y no funcionaba: un
`legend` mide su `width: 100%` contra la caja de CONTENIDO del `fieldset`, y el
navegador le reserva a ese `fieldset` un relleno lateral propio que nadie había
quitado. La banda del título quedaba 21 px más estrecha que la tarjeta, flotando
por dentro en vez de tocar los bordes. Se intentó tapar con `float: left`, que
es exactamente el tipo de parche que aparece cuando se unifica por CSS en vez de
por componente.

Con un `div` la cabecera es un hijo normal y la banda llega al borde sin
trucos. El grupo se sigue anunciando: `role="group"` con `aria-labelledby` es lo
que la especificación de ARIA da como equivalente de `fieldset`/`legend`, y es
además lo que hace upstream, que usa `div.panel` con su título y ningún
`fieldset`.
*/
export function Panel({
  titulo,
  acciones,
  agrupa = false,
  children,
  className,
}: {
  /*
  Sin título, el panel sólo agrupa: no se le inventa un rótulo.

  Admite nodo y no sólo cadena porque hay títulos que llevan formato —el visor
  de logs pone el nombre del fichero en monoespaciada—, y un componente que sólo
  acepta texto plano obliga a la pantalla a saltárselo y a replicar el marcado,
  que es justo lo que esto viene a evitar.
  */
  titulo?: ReactNode
  /** Lo que va a la derecha de la cabecera. */
  acciones?: ReactNode
  /*
  Anunciar el panel como un GRUPO con nombre. Sólo donde de verdad agrupa
  controles relacionados —los bloques de Settings y de DHCP, que son lo que
  antes era un `fieldset`—; no en un panel que contiene una gráfica o una
  tabla, donde el `h2` ya da la estructura y el rol sobra.

  No es cosmético: puesto en todos, el panel de «Query Response Types» pasaba a
  llamarse igual que la gráfica que contiene, y un lector de pantalla decía el
  mismo nombre dos veces seguidas.
  */
  agrupa?: boolean
  children: ReactNode
  className?: string
}) {
  const id = useId()
  const clases = [styles.panel, titulo == null ? styles.sinCabecera : null, className]
    .filter(Boolean)
    .join(' ')

  if (titulo == null) return <div className={clases}>{children}</div>

  return (
    <div className={clases} role={agrupa ? 'group' : undefined} aria-labelledby={agrupa ? id : undefined}>
      <div className={styles.cabecera}>
        <h2 className={styles.titulo} id={id}>
          {titulo}
        </h2>
        {acciones}
      </div>
      {children}
    </div>
  )
}

/*
El cuerpo del panel: el relleno que separa el contenido de sus bordes.

Va como componente y no como una clase que cada pantalla compone, por la misma
razón que el panel: lo que se comparte es la PIEZA, no una regla suelta. Es
opcional porque hay paneles cuyo contenido llega a los bordes a propósito —los
bloques de Settings, cuyas filas traen su propio relleno, y las tablas—.

`className` es para las variantes que sí existen: el visor de logs aprieta su
lista y el panel de «Top» del Dashboard recorta el aire de arriba.
*/
export function Cuerpo({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={[styles.cuerpo, className].filter(Boolean).join(' ')}>{children}</div>
}
