import { Tag } from '../../ui/Tag'
import { useState } from 'react'
import type { ResourceRecord } from '../../api/records'
import { recordCells, recordFooter, type Cell } from './record-view'
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
const LONG_ONES = [
  'Public Key:',
  'Signature:',
  'Digest:',
  'Fingerprint:',
  'Certificate Association Data:',
  'Computed Digests:',
]

const CUTOFF = 64

function Value({ label, value }: { label: string; value: string }) {
  const [whole, setEntero] = useState(false)
  const truncable = LONG_ONES.includes(label) && value.length > CUTOFF

  if (!truncable || whole) {
    return <span className={styles.key}>{value}</span>
  }

  return (
    <>
      <span className={styles.key}>{value.slice(0, CUTOFF)}… </span>
      <button type="button" className={styles.showIt} onClick={() => setEntero(true)}>
        show full
      </button>
    </>
  )
}

function Bloque({ cell }: { cell: Cell }) {
  switch (cell.cls) {
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
              {cell.headers.map((c) => (
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
          {cell.pairs.map((p) => (
            <div key={p.label} style={{ display: 'contents' }}>
              <dt>{p.label}</dt>
              <dd>
                <Value label={p.label} value={p.value} />
              </dd>
            </div>
          ))}
        </dl>
      )
  }
}

export function DataCell({
  record,
  notifyFailedFor,
}: {
  record: ResourceRecord
  /** The name servers the notify failed for. */
  notifyFailedFor?: string[]
}) {
  const cells = recordCells(record)
  const footer = recordFooter(record)

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
          <div key={p.label}>
            <b>{p.label}</b> {p.value}
          </div>
        ))}
        {record.comments != null && record.comments.length > 0 && (
          <div>
            <b>Comments:</b>
            <pre className={styles.output}>{record.comments}</pre>
          </div>
        )}
      </div>
    </>
  )
}
