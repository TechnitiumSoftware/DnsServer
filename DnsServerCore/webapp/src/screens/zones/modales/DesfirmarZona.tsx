import { useEffect, useState } from 'react'
import { unsignZone } from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'

/*
`modalDnssecUnsignZone` (zone.js:6673 y 6681). No tiene formulario: es un modal
de confirmación con tres avisos que se copian enteros, porque explican una
secuencia que si se hace mal deja la zona irresoluble.
*/

export function DesfirmarZona({
  zone,
  abierto,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (abierto) setAviso(null)
  }, [abierto])

  async function desfirmar() {
    setOcupado(true)
    const outcome = await unsignZone(token, zone, node)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Zone Unsigned!', text: 'The primary zone was unsigned successfully.' })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Unsign Zone - ${zone === '.' ? '<root>' : zone}`}
      acciones={
        <>
          <Button variant="danger" disabled={ocupado} onClick={() => void desfirmar()}>
            Unsign Zone
          </Button>
        </>
      }
    >
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

      <div className={`${styles.nota} ${styles.notaAviso}`}>
        <b>Warning!</b> Unsigning the zone without removing all DS records from its parent zone will cause
        DNSSEC validating recursive resolvers to mark the zone as bogus and fail to resolve it.
      </div>

      <div className={`${styles.nota} ${styles.notaAviso}`}>
        <b>Warning!</b> Make sure that you have removed all of the DS records from the parent zone and
        sufficient time has passed before unsigning this zone. You MUST wait for at least the number of
        seconds specified by the DS record&apos;s TTL value to elapse before unsigning the zone to ensure
        that all recursive resolvers would have expired the DS records from its cache. For example, if you
        have DS records at the parent zone with TTL value set to 86400 then you must wait for 86400 seconds
        (24 hours) to pass after you delete the DS records from the parent zone. Once you have ensured that
        you have waited for the appropriate time then you can unsign the zone safely.
      </div>

      <div className={`${styles.nota} ${styles.notaInfo}`}>
        <b>Note!</b> You can find out the TTL value of DS records for your zone by querying for DS records
        using the DNS Client tab.
      </div>

      <div className={`${styles.nota} ${styles.notaAviso}`}>
        <b>Warning!</b> Unsigning the zone will permanently delete all of the private keys associated with
        it. Consider taking a backup before proceeding.
      </div>

      <p className={styles.parrafo}>Are you sure you want to proceed to unsign the zone now?</p>
    </Dialog>
  )
}
