import type { ReactNode } from 'react'
import styles from './Panel.module.css'

/*
La caja con borde de la consola. Ver `Panel.module.css` para por qué existe y de
dónde salen sus valores.

`titulo` es opcional: hay paneles que sólo agrupan —el `fieldset` de SSO, sin ir
más lejos— y ponerles un rótulo que repita el título de la pantalla es ruido.
`acciones` es lo que va a la derecha de la cabecera.

Cuando agrupa campos de formulario se pide `as="fieldset"`, y entonces la
cabecera ES el `<legend>` y no un `div` que lo contenga: un `legend` metido
dentro de otro elemento deja de ser el rótulo del grupo y pasa a ser texto. Por
eso esa variante no admite acciones —no hay ninguna hoy— en vez de fingir que sí.
*/
export function Panel({
  titulo,
  acciones,
  children,
  className,
  as: Como = 'div',
}: {
  titulo?: string
  acciones?: ReactNode
  children: ReactNode
  className?: string
  /** `fieldset` cuando el panel agrupa campos de formulario. */
  as?: 'div' | 'fieldset'
}) {
  const clases = [styles.panel, titulo == null ? styles.sinCabecera : null, className]
    .filter(Boolean)
    .join(' ')

  if (Como === 'fieldset') {
    return (
      <fieldset className={clases}>
        {titulo != null && <legend className={`${styles.cabecera} ${styles.titulo}`}>{titulo}</legend>}
        {children}
      </fieldset>
    )
  }

  return (
    <div className={clases}>
      {titulo != null && (
        <div className={styles.cabecera}>
          <h2 className={styles.titulo}>{titulo}</h2>
          {acciones}
        </div>
      )}
      {children}
    </div>
  )
}
