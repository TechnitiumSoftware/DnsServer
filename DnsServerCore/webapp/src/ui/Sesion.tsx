import { Tag } from './Tag'
import styles from './Sesion.module.css'
import text from './texto.module.css'

/** What the three sessions tables need from a session. */
export interface Session {
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
export function SessionCell({ session }: { session: Pick<Session, 'partialToken' | 'tokenName' | 'isCurrentSession' | 'type'> }) {
  const label =
    session.type === 'Standard' ? (
      <Tag>Standard</Tag>
    ) : session.type === 'ApiToken' ? (
      <Tag tone="info">API Token</Tag>
    ) : session.type === 'ClusterApiToken' ? (
      <Tag tone="info">Cluster API Token</Tag>
    ) : (
      <Tag tone="warn">Unknown</Tag>
    )

  return (
    <>
      {session.tokenName != null && <div>{session.tokenName}</div>}
      <div className={text.mono}>{`[${session.partialToken}]`}</div>
      {session.isCurrentSession && <div>(current)</div>}
      <div className={styles.label}>{label}</div>
    </>
  )
}

/** The "Last Seen" cell: the date, and beneath it how long ago. */
export function LastSeenCell({ date, hace }: { date: string; hace: string }) {
  return (
    <>
      <div className={text.mono}>{date}</div>
      <div className={styles.age}>{`(${hace})`}</div>
    </>
  )
}

/** La celda «User Agent». */
export function AgentCell({ children }: { children: string }) {
  return <span className={styles.agente}>{children}</span>
}
