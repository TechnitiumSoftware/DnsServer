import { useEffect, useState } from 'react'
import { convertZone } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { GroupRow } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalConvertZone` (zone.js:1387 and 1443).

**There are three destinations, not seven**: Primary, Forwarder and Catalog. And
which of them are enabled and which comes selected depends on the source type,
through a table that follows from nothing — for example, a Primary can only go to
Forwarder, and a Secondary Catalog only to Catalog. It is copied whole.

This screen's mockup drew "Secondary / Forwarder / Catalog": Secondary is not a
possible destination and Primary was missing. Corrected against the code.
*/

export type ConversionTarget = 'Primary' | 'Forwarder' | 'Catalog'

export interface ConversionTable {
  enabled2: ConversionTarget[]
  byDefault: ConversionTarget | null
}

export function conversionTargets(sourceType: string): ConversionTable {
  switch (sourceType) {
    case 'Primary':
      return { enabled2: ['Forwarder'], byDefault: 'Forwarder' }
    case 'Secondary':
    case 'SecondaryForwarder':
      return { enabled2: ['Primary', 'Forwarder'], byDefault: 'Primary' }
    case 'Forwarder':
      return { enabled2: ['Primary'], byDefault: 'Primary' }
    case 'SecondaryCatalog':
      return { enabled2: ['Catalog'], byDefault: 'Catalog' }
    default:
      return { enabled2: [], byDefault: null }
  }
}

const LABELS: Record<ConversionTarget, string> = {
  Primary: 'Primary Zone',
  Forwarder: 'Conditional Forwarder Zone',
  Catalog: 'Catalog Zone',
}

export function ConvertZone({
  zone,
  sourceType,
  open,
  token,
  node = '',
  onClose,
  onDone,
}: {
  zone: string
  sourceType: string
  open: boolean
  token: string | null
  node?: string
  onClose: () => void
  onDone: (a: Notice) => void
}) {
  const table = conversionTargets(sourceType)
  const [target, setDestino] = useState<ConversionTarget | null>(table.byDefault)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setDestino(conversionTargets(sourceType).byDefault)
    setNotice(null)
  }, [open, sourceType])

  async function convert() {
    if (target == null) return

    setBusy(true)
    const outcome = await convertZone(token, zone, target, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    onDone({ type: 'success', title: 'Zone Converted!', text: 'The zone was converted successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={`Convert Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy || target == null} onClick={() => void convert()}>
            Convert Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.fields}>
        <GroupRow modal label="Convert To">
          {(['Primary', 'Forwarder', 'Catalog'] as ConversionTarget[]).map((d) => (
            <label key={d} className={styles.chk}>
              <input
                type="radio"
                name="convertTo"
                disabled={!table.enabled2.includes(d)}
                checked={target === d}
                onChange={() => setDestino(d)}
              />
              {LABELS[d]}
            </label>
          ))}
        </GroupRow>

        <Alert type="info" title="Note!">
          The conversion process may take a while depending on the number of records the zone
          has. When converting a Secondary Catalog zone to a Catalog zone, all member zones too will be
          converted to either Primary or Conditional Forwarder zone depending on their existing zone type.
          Please be patient till the conversion process completes.
        </Alert>
      </div>
    </Dialog>
  )
}
