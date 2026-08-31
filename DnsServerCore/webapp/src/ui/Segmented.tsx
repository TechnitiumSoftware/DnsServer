import styles from './Segmented.module.css'

/*
Pick one of a handful of values, with all of them in view. See the styles module
for why it exists.

`comoPestanas` changes the semantics, not the look: a tab group governs a panel and
is announced with `role="tab"` and `aria-selected`; a group of options —the
Dashboard's period— are state buttons and are announced with `aria-pressed`. They
look alike and are not the same thing, so the caller decides.
*/
export function Segmented<T extends string>({
  options,
  active,
  onChoose,
  label,
  comoPestanas = false,
}: {
  options: { id: T; label: string }[]
  active: T
  onChoose: (id: T) => void
  /** The group's name, for whoever does not see the screen. */
  label: string
  comoPestanas?: boolean
}) {
  return (
    <div
      className={styles.seg}
      role={comoPestanas ? 'tablist' : 'group'}
      aria-label={label}
    >
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          className={styles.option}
          role={comoPestanas ? 'tab' : undefined}
          aria-selected={comoPestanas ? o.id === active : undefined}
          aria-pressed={comoPestanas ? undefined : o.id === active}
          onClick={() => onChoose(o.id)}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
