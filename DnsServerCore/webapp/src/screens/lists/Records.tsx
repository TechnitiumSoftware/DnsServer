import { Chip, Tag } from '../../ui/Tag'
import { Button } from '../../ui/Button'
import { useState } from 'react'
import type { DnsRecord } from '../../api/zonelists'
import { rdataEntries, extras, meta, ttlPartido, type Entry } from './record'
import tbl from '../../ui/Table.module.css'
import { Table } from '../../ui/Table'
import styles from './Lists.module.css'

/*
The table that replaces the `<pre>` with the raw JSON.

Only HOW it reads changes: there is not one new control. The two row buttons
—"RRSIG" and "Glue"— call no endpoint: they expand fields that already came in
the same JSON (`dnssecRecords` and `glueRecords`) and that in upstream's dump read
just as badly as the rest.
*/

// The same cut-off as in Zones: it was 48 here and 64 there, for the same control.
const CORTE = 64

function Value({ e }: { e: Entry }) {
  const [open, setOpen] = useState(false)

  if (!e.long || open) return <span className={styles.key}>{e.value}</span>

  return (
    <>
      <span className={styles.key}>{e.value.slice(0, CORTE)}…</span>{' '}
      <button type="button" className={styles.verlo} onClick={() => setOpen(true)}>
        show full
      </button>
    </>
  )
}

function Kv({ entries }: { entries: Entry[] }) {
  if (entries.length === 0) return null
  return (
    <dl className={styles.kv}>
      {entries.map((e) => (
        <div key={e.key} style={{ display: 'contents' }}>
          <dt>{e.key}</dt>
          <dd>
            <Value e={e} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

function Row({ r, withDnssec, node }: { r: DnsRecord; withDnssec: boolean; node: string }) {
  const [firmas, setFirmas] = useState(false)
  const [glue, setGlue] = useState(false)

  const ttl = ttlPartido(r)
  const name = r.nameIdn ?? r.name
  // The name always matches the open node; it is only said when it does NOT.
  const nombreDistinto = r.name !== node && name !== node

  return (
    <tr>
      <td>
        <Chip>{r.type}</Chip>
        {nombreDistinto && <span className={styles.name}>{name === '' ? '<ROOT>' : name}</span>}
      </td>
      <td className={styles.ttl}>
        {ttl.value} {ttl.humano && <small>({ttl.humano})</small>}
      </td>
      <td>
        <Kv entries={[...rdataEntries(r.rData), ...extras(r)]} />
        <div className={styles.meta} title={r.lastUsedOn}>
          {meta(r).join(' · ')}
        </div>
        {firmas && r.dnssecRecords && (
          <pre className={styles.firmas}>{r.dnssecRecords.join('\n')}</pre>
        )}
        {glue && r.glueRecords && <pre className={styles.firmas}>{r.glueRecords.join('\n')}</pre>}
      </td>
      {withDnssec && (
        <td>
          <Tag tone={r.dnssecStatus === 'Secure' ? 'ok' : 'neutral'}>
            {r.dnssecStatus ?? '—'}
          </Tag>
        </td>
      )}
      <td className={tbl.actionsCell}>
        <div className={tbl.actions}>
          {r.glueRecords && (
            <Button
              size="sm"
              aria-pressed={glue}
              onClick={() => setGlue((v) => !v)}
            >
              Glue
            </Button>
          )}
          {r.dnssecRecords && (
            <Button
              size="sm"
              aria-pressed={firmas}
              onClick={() => setFirmas((v) => !v)}
            >
              RRSIG
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}

export function ResourceRecords({
  records,
  withDnssec,
  node,
}: {
  records: DnsRecord[]
  /** The DNSSEC column belongs to Cache only; elsewhere it drops to the grey line. */
  withDnssec: boolean
  node: string
}) {
  return (
    <Table
      header={
        <>
          <th style={{ width: 110 }}>Type</th>
          <th style={{ width: 120 }}>TTL</th>
          <th>Data</th>
          {withDnssec && <th style={{ width: 100 }}>DNSSEC</th>}
          <th style={{ width: 120 }}>
            <span className="sr-only" />
          </th>
        </>
      }
    >
      {records.map((r, i) => (
        <Row key={`${r.name}|${r.type}|${i}`} r={r} withDnssec={withDnssec} node={node} />
      ))}
    </Table>
  )
}
