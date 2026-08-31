import { Fragment } from 'react'
import { PIE } from '../app/pie'
import styles from './PieDeEnlaces.module.css'

/** Los enlaces del pie de upstream. Ver `app/pie.ts` y el módulo de estilos. */
export function PieDeEnlaces({ className }: { className?: string }) {
  return (
    <div className={[styles.pie, className].filter(Boolean).join(' ')}>
      {PIE.map((e, i) => (
        <Fragment key={e.href}>
          {i > 0 && <span className={styles.sep}> | </span>}
          <a href={e.href} aria-label={e.nombre} target="_blank" rel="noreferrer">
            {e.texto}
          </a>
        </Fragment>
      ))}
    </div>
  )
}
