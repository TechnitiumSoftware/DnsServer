import { Fragment } from 'react'
import { CREDITO_TEMA, PIE } from '../app/pie'
import styles from './PieDeEnlaces.module.css'

/**
 * Los enlaces del pie de upstream, y debajo el crédito del tema —lo único que
 * esta consola añade aquí—. Ver `app/pie.ts` y el módulo de estilos.
 */
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
      <div className={styles.credito}>
        Theme by{' '}
        <a href={CREDITO_TEMA.href} aria-label={CREDITO_TEMA.nombre} target="_blank" rel="noreferrer">
          {CREDITO_TEMA.texto}
        </a>
      </div>
    </div>
  )
}
