import { useEffect, useState } from 'react'
import { convertZone } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import type { Notice } from '../tipos'
import styles from '../Zones.module.css'
import { GroupRow } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/aviso'
import { Notifier } from '../../../ui/Avisador'

/*
`modalConvertZone` (zone.js:1387 and 1443).

**There are three destinations, not seven**: Primary, Forwarder and Catalog. And
which of them are enabled and which comes selected depends on the source type,
through a table that follows from nothing — for example, a Primary can only go to
Forwarder, and a Secondary Catalog only to Catalog. It is copied whole.

This screen's mockup drew "Secondary / Forwarder / Catalog": Secondary is not a
possible destination and Primary was missing. Corrected against the code.
*/

export type DestinoConversion = 'Primary' | 'Forwarder' | 'Catalog'

export interface TablaConversion {
  habilitados: DestinoConversion[]
  porDefecto: DestinoConversion | null
}

export function destinosDeConversion(sourceType: string): TablaConversion {
  switch (sourceType) {
    case 'Primary':
      return { habilitados: ['Forwarder'], porDefecto: 'Forwarder' }
    case 'Secondary':
    case 'SecondaryForwarder':
      return { habilitados: ['Primary', 'Forwarder'], porDefecto: 'Primary' }
    case 'Forwarder':
      return { habilitados: ['Primary'], porDefecto: 'Primary' }
    case 'SecondaryCatalog':
      return { habilitados: ['Catalog'], porDefecto: 'Catalog' }
    default:
      return { habilitados: [], porDefecto: null }
  }
}

const ETIQUETAS: Record<DestinoConversion, string> = {
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
  onCerrar,
  onHecho,
}: {
  zone: string
  sourceType: string
  open: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Notice) => void
}) {
  const table = destinosDeConversion(sourceType)
  const [destino, setDestino] = useState<DestinoConversion | null>(table.porDefecto)
  const [notice, setAviso] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setDestino(destinosDeConversion(sourceType).porDefecto)
    setAviso(null)
  }, [open, sourceType])

  async function convert() {
    if (destino == null) return

    setBusy(true)
    const outcome = await convertZone(token, zone, destino, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(noticeFromFailure(outcome))
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Zone Converted!', text: 'The zone was converted successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Convert Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy || destino == null} onClick={() => void convert()}>
            Convert Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onCerrar={() => setAviso(null)} />

      <div className={styles.fields}>
        <GroupRow modal label="Convert To">
          {(['Primary', 'Forwarder', 'Catalog'] as DestinoConversion[]).map((d) => (
            <label key={d} className={styles.chk}>
              <input
                type="radio"
                name="convertTo"
                disabled={!table.habilitados.includes(d)}
                checked={destino === d}
                onChange={() => setDestino(d)}
              />
              {ETIQUETAS[d]}
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
