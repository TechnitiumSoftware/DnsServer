import { Tag } from '../../ui/Tag'
import { useState } from 'react'
import type { Registro } from '../../api/registros'
import { celdasDeRegistro, pieDeRegistro, type Celda } from './registro-vista'
import { Tabla } from '../../ui/Table'
import styles from './Zones.module.css'

/*
A record's "Data" cell. The content is decided by `registro-vista.ts`; here it is
only drawn.

**Public keys are truncated** (Adrián's decision, 2026-08-25): a DNSKEY is 400
base64 characters and in full they make each record take up six table lines, with
the root node unreadable. The beginning is shown plus a "see full" link. Nothing
is lost: the value is still one click away.
*/

/** The labels whose value is genuinely long and worth truncating. */
const LARGOS = [
  'Public Key:',
  'Signature:',
  'Digest:',
  'Fingerprint:',
  'Certificate Association Data:',
  'Computed Digests:',
]

const CORTE = 64

function Valor({ etiqueta, valor }: { etiqueta: string; valor: string }) {
  const [entero, setEntero] = useState(false)
  const truncable = LARGOS.includes(etiqueta) && valor.length > CORTE

  if (!truncable || entero) {
    return <span className={styles.clave}>{valor}</span>
  }

  return (
    <>
      <span className={styles.clave}>{valor.slice(0, CORTE)}… </span>
      <button type="button" className={styles.verlo} onClick={() => setEntero(true)}>
        show full
      </button>
    </>
  )
}

function Bloque({ celda }: { celda: Celda }) {
  switch (celda.clase) {
    case 'valor':
      return <div className={styles.val}>{celda.texto}</div>

    case 'lineas':
      return (
        <div className={styles.val}>
          {celda.lineas.map((l, i) => (
            <div key={i}>{l}</div>
          ))}
        </div>
      )

    case 'tabla':
      return (
        <Tabla
          cabecera={
            <>
              {celda.cabeceras.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </>
          }
        >
          {celda.filas.map((fila, i) => (
            <tr key={i}>
              {fila.map((v, j) => (
                <td key={j} className={styles.mono}>
                  {v}
                </td>
              ))}
            </tr>
          ))}
        </Tabla>
      )

    case 'pares':
      return (
        <dl className={styles.kv}>
          {celda.pares.map((p) => (
            <div key={p.etiqueta} style={{ display: 'contents' }}>
              <dt>{p.etiqueta}</dt>
              <dd>
                <Valor etiqueta={p.etiqueta} valor={p.valor} />
              </dd>
            </div>
          ))}
        </dl>
      )
  }
}

export function CeldaDatos({
  registro,
  notifyFailedFor,
}: {
  registro: Registro
  /** The name servers the notify failed for. */
  notifyFailedFor?: string[]
}) {
  const celdas = celdasDeRegistro(registro)
  const pie = pieDeRegistro(registro)

  // Only on NS, and only if THAT server is in the zone's failure list.
  const notifyFallido =
    registro.type === 'NS' &&
    (notifyFailedFor ?? []).includes(String(registro.rData.nameServer ?? ''))

  return (
    <>
      {celdas.map((c, i) => (
        <Bloque key={i} celda={c} />
      ))}

      {notifyFallido && (
        <div className={styles.tags}>
          <Tag tone="warn">Notify Failed</Tag>
        </div>
      )}

      <div className={styles.meta}>
        {pie.map((p) => (
          <div key={p.etiqueta}>
            <b>{p.etiqueta}</b> {p.valor}
          </div>
        ))}
        {registro.comments != null && registro.comments.length > 0 && (
          <div>
            <b>Comments:</b>
            <pre className={styles.salida}>{registro.comments}</pre>
          </div>
        )}
      </div>
    </>
  )
}
