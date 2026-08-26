import { useEffect, useState } from 'react'
import { verDs, type InfoDs } from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Dialog } from '../../../ui/Dialog'
import { Empty, Loading } from '../../../ui/Empty'
import { fechaMinuto as fechaCorta } from '../../../lib/fechas'
import type { Aviso } from '../tipos'
import tbl from '../../../ui/Table.module.css'
import styles from '../Zones.module.css'

/*
`modalDnssecViewDs` (zone.js:6734). Es un visor: no hay nada que guardar.

La tabla original usa `rowspan` para agrupar los digests de una misma clave.
Aquí cada clave es un bloque con su propia tabla de digests, que dice lo mismo
sin depender de un `rowspan` calculado a mano.

**Las claves públicas se truncan** con un enlace «show full» (decisión de
Adrián, 2026-08-25): son 400 caracteres en base64 y enteras hacen ilegible el
nodo raíz.
*/

const CORTE = 64

function Largo({ valor }: { valor: string }) {
  const [entero, setEntero] = useState(false)
  if (valor.length <= CORTE || entero) return <span className={styles.clave}>{valor}</span>
  return (
    <>
      <span className={styles.clave}>{valor.slice(0, CORTE)}… </span>
      <button type="button" className={styles.verlo} onClick={() => setEntero(true)}>
        show full
      </button>
    </>
  )
}

export function VerDs({
  zone,
  abierto,
  token,
  node = '',
  onCerrar,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
}) {
  const [info, setInfo] = useState<InfoDs | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cargando, setCargando] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setCargando(true)
    void verDs(token, zone, node).then((r) => {
      setCargando(false)
      if (r == null) {
        setAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setInfo(r)
    })
  }, [abierto, token, zone, node])

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      ancho
      title={`View DS Info - ${zone === '.' ? '<root>' : zone}`}
    >
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

      <p className={styles.parrafo}>
        Use the DNS Key data given below to add DS records for your zone. Before adding the DS records, you
        must read and understand the following points:
      </p>
      <ul className={styles.parrafo}>
        <li>
          The Key State for a newly published DNS Key must be Ready before you can add a DS record for it.
          Adding DS record for a DNS Key with Published Key State may cause DNSSEC validation to fail for
          some DNS resolvers. A &quot;ready by&quot; timestamp is displayed to let you know when a DS record
          can be added for a DNS Key that is not &quot;Ready&quot; yet.
        </li>
        <li>
          You should add only one DS record for each Key Tag. That is, do not create multiple DS records for
          each Digest Type, instead use the Digest Type that is supported by your Domain Registrar.
        </li>
        <li>Use the provided Public Key if the Domain Registrar requires it instead of the Digest.</li>
        <li>
          When doing a Key Signing Key (KSK) rollover, you can immediately delete the old DS record after
          adding the new DS record.
        </li>
      </ul>

      {cargando ? (
        <Loading>Loading DS records…</Loading>
      ) : (info?.dsRecords ?? []).length === 0 ? (
        <Empty titulo="No DS records">This zone has no published keys yet.</Empty>
      ) : (
        (info?.dsRecords ?? []).map((ds) => (
          <div key={ds.keyTag} className={styles.grupo}>
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
                <Largo valor={ds.publicKey} />
              </dd>
            </dl>

            <div className={tbl.wrap}>
              <table className={tbl.tabla}>
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>Digest Type</th>
                    <th>Digest</th>
                  </tr>
                </thead>
                <tbody>
                  {ds.digests.map((d) => (
                    <tr key={d.digestType}>
                      <td className={styles.mono}>
                        {d.digestType} ({d.digestTypeNumber})
                      </td>
                      <td>
                        <Largo valor={d.digest} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))
      )}
    </Dialog>
  )
}
