import { Tag } from '../../ui/Tag'
import { useState } from 'react'
import type { ResourceRecord } from '../../api/registros'
import { celdasDeRegistro, pieDeRegistro, type Cell } from './registro-vista'
import { Table } from '../../ui/Table'
import styles from './Zones.module.css'

/*
A record's "Data" cell. The content is decided by `registro-vista.ts`; here it is
only drawn.

**Public keys are truncated** (Adrián's decision, 2026-08-25): a DNSKEY is 400
base64 characters and in full they make each record take up six table lines, with
the root node unreadable. The beginning is shown plus a "see full" link. Nothing
is lost: the value is still one click away.
*/

/** The labels whose value is genuinely long and worth truncating. */
const LARGOS = [
  'Public Key:',
  'Signature:',
  'Digest:',
  'Fingerprint:',
  'Certificate Association Data:',
  'Computed Digests:',
]

const CORTE = 64

function Value({ etiqueta, value }: { etiqueta: string; value: string }) {
  const [entero, setEntero] = useState(false)
  const truncable = LARGOS.includes(etiqueta) && value.length > CORTE

  if (!truncable || entero) {
    return <span className={styles.key}>{value}</span>
  }

  return (
    <>
      <span className={styles.key}>{value.slice(0, CORTE)}… </span>
      <button type="button" className={styles.verlo} onClick={() => setEntero(true)}>
        show full
      </button>
    </>
  )
}

function Bloque({ cell }: { cell: Cell }) {
  switch (cell.clase) {
    case 'value':
      return <div className={styles.val}>{cell.text}</div>

    case 'lines':
      return (
        <div className={styles.val}>
          {cell.lines.map((l, i) => (
            <div key={i}>{l}</div>
          ))}
        </div>
      )

    case 'table':
      return (
        <Table
          header={
            <>
              {cell.cabeceras.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </>
          }
        >
          {cell.rows.map((row, i) => (
            <tr key={i}>
              {row.map((v, j) => (
                <td key={j} className={styles.mono}>
                  {v}
                </td>
              ))}
            </tr>
          ))}
        </Table>
      )

    case 'pairs':
      return (
        <dl className={styles.kv}>
          {cell.pares.map((p) => (
            <div key={p.etiqueta} style={{ display: 'contents' }}>
              <dt>{p.etiqueta}</dt>
              <dd>
                <Value etiqueta={p.etiqueta} value={p.value} />
              </dd>
            </div>
          ))}
        </dl>
      )
  }
}

export function CeldaDatos({
  record,
  notifyFailedFor,
}: {
  record: ResourceRecord
  /** The name servers the notify failed for. */
  notifyFailedFor?: string[]
}) {
  const cells = celdasDeRegistro(record)
  const footer = pieDeRegistro(record)

  // Only on NS, and only if THAT server is in the zone's failure list.
  const notifyFallido =
    record.type === 'NS' &&
    (notifyFailedFor ?? []).includes(String(record.rData.nameServer ?? ''))

  return (
    <>
      {cells.map((c, i) => (
        <Bloque key={i} cell={c} />
      ))}

      {notifyFallido && (
        <div className={styles.tags}>
          <Tag tone="warn">Notify Failed</Tag>
        </div>
      )}

      <div className={styles.meta}>
        {footer.map((p) => (
          <div key={p.etiqueta}>
            <b>{p.etiqueta}</b> {p.value}
          </div>
        ))}
        {record.comments != null && record.comments.length > 0 && (
          <div>
            <b>Comments:</b>
            <pre className={styles.salida}>{record.comments}</pre>
          </div>
        )}
      </div>
    </>
  )
}
