import { useEffect, useState } from 'react'
import { convertZone } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'

/*
`modalConvertZone` (zone.js:1387 y 1443).

**Los destinos son tres, no siete**: Primary, Forwarder y Catalog. Y cuáles
están habilitados y cuál sale marcado depende del tipo de origen, con una tabla
que no se deduce de nada — por ejemplo, una Primary sólo puede ir a Forwarder,
y una Secondary Catalog sólo a Catalog. Se copia entera.

El diseño de esta pantalla dibujaba «Secondary / Forwarder / Catalog»: Secondary
no es un destino posible y Primary faltaba. Corregido contra el código.
*/

export type DestinoConversion = 'Primary' | 'Forwarder' | 'Catalog'

export interface TablaConversion {
  habilitados: DestinoConversion[]
  porDefecto: DestinoConversion | null
}

export function destinosDeConversion(tipoOrigen: string): TablaConversion {
  switch (tipoOrigen) {
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

export function ConvertirZona({
  zone,
  tipoOrigen,
  abierto,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  tipoOrigen: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const tabla = destinosDeConversion(tipoOrigen)
  const [destino, setDestino] = useState<DestinoConversion | null>(tabla.porDefecto)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setDestino(destinosDeConversion(tipoOrigen).porDefecto)
    setAviso(null)
  }, [abierto, tipoOrigen])

  async function convertir() {
    if (destino == null) return

    setOcupado(true)
    const outcome = await convertZone(token, zone, destino, node)
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
    onHecho({ type: 'success', title: 'Zone Converted!', text: 'The zone was converted successfully.' })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Convert Zone - ${zone === '.' ? '<root>' : zone}`}
      footer={
        <>
          <Button onClick={onCerrar}>Close</Button>
          <Button variant="primary" disabled={ocupado || destino == null} onClick={() => void convertir()}>
            Convert Zone
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

      <div className={styles.campos}>
        <div className={styles.fila}>
          <div className={styles.filaLab}>Convert To</div>
          <div className={styles.filaCtl}>
            {(['Primary', 'Forwarder', 'Catalog'] as DestinoConversion[]).map((d) => (
              <label key={d} className={styles.chk}>
                <input
                  type="radio"
                  name="convertTo"
                  disabled={!tabla.habilitados.includes(d)}
                  checked={destino === d}
                  onChange={() => setDestino(d)}
                />
                {ETIQUETAS[d]}
              </label>
            ))}
          </div>
        </div>

        <div className={`${styles.nota} ${styles.notaInfo}`}>
          <b>Note!</b> The conversion process may take a while depending on the number of records the zone
          has. When converting a Secondary Catalog zone to a Catalog zone, all member zones too will be
          converted to either Primary or Conditional Forwarder zone depending on their existing zone type.
          Please be patient till the conversion process completes.
        </div>
      </div>
    </Dialog>
  )
}
