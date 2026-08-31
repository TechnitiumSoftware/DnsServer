import styles from './Lists.module.css'
import { Icon } from '../../ui/Icon'

/*
The domain tree.

Upstream draws a FLAT LIST: `[refresh]`, `[up]` and the node's children
(other-zones.js:120-137). Here it is drawn as a tree, which is the same thing put
another way: the root, the current node's chain of ancestors —each of them being
its child's `[up]`— and below them the children the server returns.

`zones` already brings FULL domain names, so the labels are printed as they come
and navigating is handing the server the string you can see.
*/

/** Every ancestor of the domain, from the root down and not including it. */
export function ancestors(domain: string): string[] {
  const salida: string[] = []
  let d = domain
  for (;;) {
    const i = d.indexOf('.')
    if (i === -1) break
    d = d.substring(i + 1)
    salida.push(d)
  }
  return salida.reverse()
}

export function Tree({
  domain,
  domainIdn,
  zones,
  onNavegar,
}: {
  domain: string
  domainIdn?: string
  zones: string[]
  /** `arriba` marks the navigation as upstream's [up] link. */
  onNavegar: (domain: string, up?: boolean) => void
}) {
  const string = ancestors(domain)
  const atRoot = domain === ''

  // Each ancestor nests one level more; the children hang off the current node.
  let tree = (
    <div className={styles.lvl}>
      {zones.map((z) => (
        <button key={z} type="button" className={styles.node} onClick={() => onNavegar(z)}>
          <span className={styles.car}><Icon name="chevronRight" tam={12} /></span>
          <span className={styles.label}>{z}</span>
        </button>
      ))}
    </div>
  )

  if (!atRoot) {
    tree = (
      <div className={styles.lvl}>
        <button type="button" className={styles.node} aria-current="true" disabled>
          <span className={styles.car}><Icon name="chevronDown" tam={12} /></span>
          <span className={styles.label}>{domainIdn ?? domain}</span>
        </button>
        {tree}
      </div>
    )

    for (const padre of [...string].reverse()) {
      const inside = tree
      tree = (
        <div className={styles.lvl}>
          <button
            type="button"
            className={styles.node}
            onClick={() => onNavegar(padre, true)}
          >
            <span className={styles.car}><Icon name="chevronDown" tam={12} /></span>
            <span className={styles.label}>{padre}</span>
          </button>
          {inside}
        </div>
      )
    }
  }

  return (
    <div>
      <button
        type="button"
        className={styles.node}
        aria-current={atRoot ? 'true' : undefined}
        onClick={atRoot ? undefined : () => onNavegar('', true)}
        disabled={atRoot}
      >
        <span className={styles.car}><Icon name="chevronDown" tam={12} /></span>
        <span className={styles.label}>&lt;ROOT&gt;</span>
      </button>
      {tree}
    </div>
  )
}
