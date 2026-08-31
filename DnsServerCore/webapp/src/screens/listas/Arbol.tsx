import styles from './Listas.module.css'
import { Icono } from '../../ui/Icono'

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
export function antepasados(domain: string): string[] {
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

export function Arbol({
  domain,
  domainIdn,
  zones,
  onNavegar,
}: {
  domain: string
  domainIdn?: string
  zones: string[]
  /** `arriba` marks the navigation as upstream's [up] link. */
  onNavegar: (domain: string, arriba?: boolean) => void
}) {
  const cadena = antepasados(domain)
  const enRaiz = domain === ''

  // Each ancestor nests one level more; the children hang off the current node.
  let arbol = (
    <div className={styles.lvl}>
      {zones.map((z) => (
        <button key={z} type="button" className={styles.node} onClick={() => onNavegar(z)}>
          <span className={styles.car}><Icono nombre="chevronDerecha" tam={12} /></span>
          <span className={styles.etiqueta}>{z}</span>
        </button>
      ))}
    </div>
  )

  if (!enRaiz) {
    arbol = (
      <div className={styles.lvl}>
        <button type="button" className={styles.node} aria-current="true" disabled>
          <span className={styles.car}><Icono nombre="chevronAbajo" tam={12} /></span>
          <span className={styles.etiqueta}>{domainIdn ?? domain}</span>
        </button>
        {arbol}
      </div>
    )

    for (const padre of [...cadena].reverse()) {
      const dentro = arbol
      arbol = (
        <div className={styles.lvl}>
          <button
            type="button"
            className={styles.node}
            onClick={() => onNavegar(padre, true)}
          >
            <span className={styles.car}><Icono nombre="chevronAbajo" tam={12} /></span>
            <span className={styles.etiqueta}>{padre}</span>
          </button>
          {dentro}
        </div>
      )
    }
  }

  return (
    <div>
      <button
        type="button"
        className={styles.node}
        aria-current={enRaiz ? 'true' : undefined}
        onClick={enRaiz ? undefined : () => onNavegar('', true)}
        disabled={enRaiz}
      >
        <span className={styles.car}><Icono nombre="chevronAbajo" tam={12} /></span>
        <span className={styles.etiqueta}>&lt;ROOT&gt;</span>
      </button>
      {arbol}
    </div>
  )
}
