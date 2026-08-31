import { useEffect, useState } from 'react'
import { unsignZone } from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalDnssecUnsignZone` (zone.js:6673 and 6681). It has no form: it is a
confirmation modal with three warnings copied whole, because they explain a
sequence that, done wrong, leaves the zone unresolvable.
*/

export function UnsignZone({
  zone,
  open,
  token,
  node = '',
  onClose,
  onDone,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onClose: () => void
  onDone: (a: Notice) => void
}) {
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (open) setNotice(null)
  }, [open])

  async function unsign() {
    setBusy(true)
    const outcome = await unsignZone(token, zone, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    onDone({ type: 'success', title: 'Zone Unsigned!', text: 'The primary zone was unsigned successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={`Unsign Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="danger" disabled={busy} onClick={() => void unsign()}>
            Unsign Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <Alert type="warning" title="Warning!">
        Unsigning the zone without removing all DS records from its parent zone will cause
        DNSSEC validating recursive resolvers to mark the zone as bogus and fail to resolve it.
      </Alert>

      <Alert type="warning" title="Warning!">
        Make sure that you have removed all of the DS records from the parent zone and
        sufficient time has passed before unsigning this zone. You MUST wait for at least the number of
        seconds specified by the DS record&apos;s TTL value to elapse before unsigning the zone to ensure
        that all recursive resolvers would have expired the DS records from its cache. For example, if you
        have DS records at the parent zone with TTL value set to 86400 then you must wait for 86400 seconds
        (24 hours) to pass after you delete the DS records from the parent zone. Once you have ensured that
        you have waited for the appropriate time then you can unsign the zone safely.
      </Alert>

      <Alert type="info" title="Note!">
        You can find out the TTL value of DS records for your zone by querying for DS records
        using the DNS Client tab.
      </Alert>

      <Alert type="warning" title="Warning!">
        Unsigning the zone will permanently delete all of the private keys associated with
        it. Consider taking a backup before proceeding.
      </Alert>

      <p className={styles.paragraph}>Are you sure you want to proceed to unsign the zone now?</p>
    </Dialog>
  )
}
