import { useEffect, useRef, useState } from 'react'
import { cloneZone } from '../../../api/zones'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { LabeledInput } from '../../../ui/Field'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/** `modalCloneZone` (zone.js:1332 and 1346). */
export function CloneZone({
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
  const [blank, setNueva] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const field = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setNueva('')
    setNotice(null)
    field.current?.focus()
  }, [open])

  async function clone() {
    if (blank === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter a domain name for the new zone.' })
      field.current?.focus()
      return
    }

    setBusy(true)
    const outcome = await cloneZone(token, blank, zone, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    // Upstream's text is like this, with that half-finished sentence. Copied literally.
    onDone({ type: 'success', title: 'Zone Cloned!', text: 'Zone was cloned from successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={`Clone Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void clone()}>
            Clone Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <div className={styles.fields}>
        {/* The source is read-only: upstream keeps it in a hidden input. */}
        <LabeledInput label="Source Zone" mono readOnly value={zone} />
        <LabeledInput
          label="New Zone"
          placeholder="example.com"
          mono
          ref={field}
          value={blank}
          onChange={(e) => setNueva(e.target.value)}
        />
      </div>
    </Dialog>
  )
}
