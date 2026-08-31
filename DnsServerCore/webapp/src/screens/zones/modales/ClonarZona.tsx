import { useEffect, useRef, useState } from 'react'
import { cloneZone } from '../../../api/zones'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { LabeledInput } from '../../../ui/Field'
import type { Notice } from '../tipos'
import styles from '../Zones.module.css'
import { noticeFromFailure } from '../../../lib/aviso'
import { Notifier } from '../../../ui/Avisador'

/** `modalCloneZone` (zone.js:1332 y 1346). */
export function ClonarZona({
  zone,
  open,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Notice) => void
}) {
  const [blank, setNueva] = useState('')
  const [notice, setAviso] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const field = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setNueva('')
    setAviso(null)
    field.current?.focus()
  }, [open])

  async function clonar() {
    if (blank === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a domain name for the new zone.' })
      field.current?.focus()
      return
    }

    setBusy(true)
    const outcome = await cloneZone(token, blank, zone, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    onCerrar()
    // Upstream's text is like this, with that half-finished sentence. Copied literally.
    onHecho({ type: 'success', title: 'Zone Cloned!', text: 'Zone was cloned from successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Clone Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void clonar()}>
            Clone Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onCerrar={() => setAviso(null)} />
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
