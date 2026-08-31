import { Tag } from './Tag'
import styles from './Sesion.module.css'
import texto from './texto.module.css'

/** What the three sessions tables need from a session. */
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
The "Session" cell: the token name if it has one, the partial token, "(current)"
if it is this one, and the type as a tag. It is upstream's order
(`auth.js:694-719`) and all three tables paint it the same.

A type that is not recognised comes out as "Unknown" in amber, which is what
upstream does with its `default`: staying silent would be worse than saying it is
not known.
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

/** The "Last Seen" cell: the date, and beneath it how long ago. */
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
