import { useEffect, useState } from 'react'
import { viewDs, type InfoDs } from '../../../api/dnssec'
import { Dialog } from '../../../ui/Dialog'
import { Empty, Loading } from '../../../ui/Empty'
import { fechaMinuto as fechaCorta } from '../../../lib/dates'
import type { Notice } from '../types'
import { Table } from '../../../ui/Table'
import styles from '../Zones.module.css'
import { Notifier } from '../../../ui/Notifier'

/*
`modalDnssecViewDs` (zone.js:6734). It is a viewer: there is nothing to save.

The original table uses `rowspan` to group the digests of one key. Here each key
is a block with its own digest table, which says the same thing without depending
on a `rowspan` calculated by hand.

**Public keys are truncated** with a "show full" link (Adrián's decision,
2026-08-25): they are 400 base64 characters and in full they make the root node
unreadable.
*/

const CUTOFF = 64

function Long({ value }: { value: string }) {
  const [whole, setEntero] = useState(false)
  if (value.length <= CUTOFF || whole) return <span className={styles.key}>{value}</span>
  return (
    <>
      <span className={styles.key}>{value.slice(0, CUTOFF)}… </span>
      <button type="button" className={styles.showIt} onClick={() => setEntero(true)}>
        show full
      </button>
    </>
  )
}

export function ViewDs({
  zone,
  open,
  token,
  node = '',
  onClose,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onClose: () => void
}) {
  const [info, setInfo] = useState<InfoDs | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setLoading(true)
    void viewDs(token, zone, node).then((r) => {
      setLoading(false)
      if (r == null) {
        setNotice({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setInfo(r)
    })
  }, [open, token, zone, node])

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="wide"
      title={`View DS Info - ${zone === '.' ? '<root>' : zone}`}
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <p className={styles.paragraph}>
        Use the DNS Key data given below to add DS records for your zone. Before adding the DS records, you
        must read and understand the following points:
      </p>
      <ul className={styles.paragraph}>
        <li>
          The Key State for a newly published DNS Key must be Ready before you can add a DS record for it.
          Adding DS record for a DNS Key with Published Key State may cause DNSSEC validation to fail for
          some DNS resolvers. A &quot;ready by&quot; timestamp is displayed to let you know when a DS record
          can be added for a DNS Key that is not &quot;Ready&quot; yet.
        </li>
        <li>
          You should add only one DS record for each Key Tag. That is, do not create multiple DS records for
          each Digest Type, instead use the Digest Type that is supported by your Domain Register.
        </li>
        <li>Use the provided Public Key if the Domain Register requires it instead of the Digest.</li>
        <li>
          When doing a Key Signing Key (KSK) rollover, you can immediately delete the old DS record after
          adding the new DS record.
        </li>
      </ul>

      {loading ? (
        <Loading>Loading DS records…</Loading>
      ) : (info?.dsRecords ?? []).length === 0 ? (
        <Empty title="No DS records">This zone has no published keys yet.</Empty>
      ) : (
        (info?.dsRecords ?? []).map((ds) => (
          <div key={ds.keyTag} className={styles.group}>
            <dl className={styles.kv}>
              <dt>Key Tag</dt>
              <dd>{ds.keyTag}</dd>
              <dt>Key State</dt>
              <dd>
                {ds.dnsKeyState}
                {ds.dnsKeyState === 'Active' && ds.isRetiring ? ' (retiring)' : ''}
                {ds.dnsKeyStateReadyBy != null ? ` (ready by: ${fechaCorta(ds.dnsKeyStateReadyBy)})` : ''}
              </dd>
              <dt>Algorithm</dt>
              <dd>
                {ds.algorithm} ({ds.algorithmNumber})
              </dd>
              <dt>Public Key</dt>
              <dd>
                <Long value={ds.publicKey} />
              </dd>
            </dl>

            <Table
              header={
                <>
                  <th style={{ width: 140 }}>Digest Type</th>
                  <th>Digest</th>
                </>
              }
            >
              {ds.digests.map((d) => (
                <tr key={d.digestType}>
                  <td className={styles.mono}>
                    {d.digestType} ({d.digestTypeNumber})
                  </td>
                  <td>
                    <Long value={d.digest} />
                  </td>
                </tr>
              ))}
            </Table>
          </div>
        ))
      )}
    </Dialog>
  )
}
