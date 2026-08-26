import styles from './Listas.module.css'
import { Icono } from '../../ui/Icono'

/*
El árbol de dominios.

Upstream pinta una LISTA PLANA: `[refresh]`, `[up]` y los hijos del nodo
(other-zones.js:120-137). Aquí se pinta como árbol, que es lo mismo dicho de
otra forma: la raíz, la cadena de antepasados del nodo actual —cada uno de ellos
es el `[up]` de su hijo— y debajo los hijos que devuelve el servidor.

`zones` ya trae nombres de dominio COMPLETOS, así que las etiquetas se imprimen
tal cual y navegar es pasarle al servidor la cadena que se ve.
*/

/** Todos los antepasados del dominio, de la raíz hacia abajo y sin incluirlo. */
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
  /** `arriba` marca la navegación como el enlace [up] de upstream. */
  onNavegar: (domain: string, arriba?: boolean) => void
}) {
  const cadena = antepasados(domain)
  const enRaiz = domain === ''

  // Cada antepasado anida un nivel más; los hijos cuelgan del nodo actual.
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
