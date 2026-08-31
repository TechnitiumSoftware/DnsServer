import { Fragment } from 'react'
import { CREDITO_TEMA, FOOTER } from '../app/pie'
import styles from './PieDeEnlaces.module.css'

/**
 * Upstream's footer links, and beneath them the theme credit —the only thing this
 * console adds here—. See `app/pie.ts` and the styles module.
 */
export function PieDeEnlaces({ className }: { className?: string }) {
  return (
    <div className={[styles.footer, className].filter(Boolean).join(' ')}>
      {FOOTER.map((e, i) => (
        <Fragment key={e.href}>
          {i > 0 && <span className={styles.sep}> | </span>}
          <a href={e.href} aria-label={e.name} target="_blank" rel="noreferrer">
            {e.text}
          </a>
        </Fragment>
      ))}
      <div className={styles.credito}>
        Theme by{' '}
        <a href={CREDITO_TEMA.href} aria-label={CREDITO_TEMA.name} target="_blank" rel="noreferrer">
          {CREDITO_TEMA.text}
        </a>
      </div>
    </div>
  )
}
