import { Tag } from '../../ui/Tag'
import { useState } from 'react'
import type { Registro } from '../../api/registros'
import { celdasDeRegistro, pieDeRegistro, type Celda } from './registro-vista'
import tbl from '../../ui/Table.module.css'
import styles from './Zones.module.css'

/*
La celda «Data» de un registro. El contenido lo decide `registro-vista.ts`;
aquí sólo se pinta.

**Las claves públicas se truncan** (decisión de Adrián, 2026-08-25): un DNSKEY
son 400 caracteres en base64 y enteros hacen que cada registro ocupe seis líneas
de tabla, con el nodo raíz ilegible. Se enseña el principio y un enlace «ver
completa». No se pierde nada: el valor sigue estando a un clic.
*/

/** Los rótulos cuyo valor es largo de verdad y merece truncarse. */
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
        <div className={tbl.wrap}>
          <table className={tbl.tabla}>
            <thead>
              <tr>
                {celda.cabeceras.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {celda.filas.map((fila, i) => (
                <tr key={i}>
                  {fila.map((v, j) => (
                    <td key={j} className={styles.mono}>
                      {v}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
  /** Los servidores de nombres a los que falló la notificación. */
  notifyFailedFor?: string[]
}) {
  const celdas = celdasDeRegistro(registro)
  const pie = pieDeRegistro(registro)

  // Sólo en NS, y sólo si ESE servidor está en la lista de fallos de la zona.
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
