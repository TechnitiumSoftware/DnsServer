import type { ReactNode } from 'react'
import { Icon } from './Icono'
import styles from './SectionHeader.module.css'

/*
A section's header. There used to be four different treatments:

  · 22 px in Zones, Cache, Allowed, Blocked, Apps, DHCP, Administration and Logs
  · 19 px in About
  · **14 px** in Settings, with the panel name in a muted `span`
  · **none at all** in Dashboard and DNS Client

The 14 px one was the worst possible place for the smallest title: Settings is the
longest screen in the console (5,400 px of scroll, 54 fields) and the one that can
take the server down. And all nine sub-tabs showed the same "Settings", so the
title was no use either for knowing where you were or for finding it with Ctrl+F.

## The composition

Above the title goes a PATH, not a kicker:

    DHCP ›
    Leases

The difference is not where it sits, it is what each thing is. A kicker is
editorial decoration —tight muted small caps— and adds nothing; a path is
navigation, and it is needed here because some names collide: "Cache" is a
top-level section AND a Settings sub-tab, and "General" or "Logging" say nothing
on their own. That is why it goes in a `nav`, in normal case, and the `h1` remains
exactly the name of the screen.

With no sub-tabs there is no path: the title is the section name, plain.

## Tags are STATE, not counts

`etiquetas` is for state pills —`Primary`, `Enabled`, `DNSSEC`—. Counts have their
place in the count bar above the table; putting them here with the same look as a
state was another of the inconsistencies: the same pill meant a figure sometimes,
a state other times and a setting others.
*/

export function SectionHeader({
  section,
  onVolver,
  title,
  labels,
  actions,
}: {
  /** The section name. Only when there are sub-tabs. */
  section?: string
  /** On a detail screen, the way back to the section. The kicker becomes that
   *  path: there used to be a "← Zones" above and a "ZONES" below, two elements
   *  saying the same thing two centimetres apart. */
  onVolver?: () => void
  /** The most specific name: the sub-tab if there is one, otherwise the section. */
  title: string
  /** STATE pills. Counts go in the count bar. */
  labels?: ReactNode
  /** Action bar, always top right. */
  actions?: ReactNode
}) {
  return (
    <div className={styles.hrow}>
      <div className={styles.izq}>
        {section != null && (
          <nav className={styles.camino} aria-label="Breadcrumb">
            {onVolver != null ? (
              <button type="button" className={styles.ctx} onClick={onVolver}>
                {section}
              </button>
            ) : (
              <span className={styles.ctx}>{section}</span>
            )}
            <Icon name="chevronRight" tam={12} className={styles.sep} />
          </nav>
        )}
        <h1 className={styles.title}>{title}</h1>
        {labels != null && <div className={styles.tags}>{labels}</div>}
      </div>
      {actions != null && <div className={styles.acts}>{actions}</div>}
    </div>
  )
}
