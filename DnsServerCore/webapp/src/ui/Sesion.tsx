import { Tag } from './Tag'
import styles from './Sesion.module.css'
import texto from './texto.module.css'

/** Lo que las tres tablas de sesiones necesitan de una sesión. */
export interface Sesion {
  partialToken: string
  tokenName: string | null
  isCurrentSession: boolean
  type: string
  lastSeen: string
  lastSeenRemoteAddress: string
  lastSeenUserAgent: string
}

/*
La celda «Session»: nombre del token si lo tiene, el token parcial, «(current)»
si es ésta, y el tipo como etiqueta. Es el orden de upstream (`auth.js:694-719`)
y las tres tablas lo pintan igual.

Un tipo que no se reconoce sale como «Unknown» en ámbar, que es lo que hace
upstream con su `default`: callarlo sería peor que decir que no se sabe.
*/
export function CeldaSesion({ sesion }: { sesion: Pick<Sesion, 'partialToken' | 'tokenName' | 'isCurrentSession' | 'type'> }) {
  const etiqueta =
    sesion.type === 'Standard' ? (
      <Tag>Standard</Tag>
    ) : sesion.type === 'ApiToken' ? (
      <Tag tone="info">API Token</Tag>
    ) : sesion.type === 'ClusterApiToken' ? (
      <Tag tone="info">Cluster API Token</Tag>
    ) : (
      <Tag tone="warn">Unknown</Tag>
    )

  return (
    <>
      {sesion.tokenName != null && <div>{sesion.tokenName}</div>}
      <div className={texto.mono}>{`[${sesion.partialToken}]`}</div>
      {sesion.isCurrentSession && <div>(current)</div>}
      <div className={styles.etiqueta}>{etiqueta}</div>
    </>
  )
}

/** La celda «Last Seen»: la fecha, y debajo cuánto hace. */
export function CeldaUltimaVez({ fecha, hace }: { fecha: string; hace: string }) {
  return (
    <>
      <div className={texto.mono}>{fecha}</div>
      <div className={styles.antiguedad}>{`(${hace})`}</div>
    </>
  )
}

/** La celda «User Agent». */
export function CeldaAgente({ children }: { children: string }) {
  return <span className={styles.agente}>{children}</span>
}
