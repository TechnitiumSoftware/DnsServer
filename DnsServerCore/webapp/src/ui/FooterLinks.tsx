import { Fragment } from 'react'
import { THEME_CREDIT, FOOTER } from '../app/footer'
import styles from './FooterLinks.module.css'

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
        <a href={THEME_CREDIT.href} aria-label={THEME_CREDIT.name} target="_blank" rel="noreferrer">
          {THEME_CREDIT.text}
        </a>
      </div>
    </div>
  )
}
