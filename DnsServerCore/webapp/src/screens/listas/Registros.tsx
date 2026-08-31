import { Chip, Tag } from '../../ui/Tag'
import { Button } from '../../ui/Button'
import { useState } from 'react'
import type { RegistroDns } from '../../api/zonelists'
import { entradasRData, extras, meta, ttlPartido, type Entrada } from './registro'
import tbl from '../../ui/Table.module.css'
import styles from './Listas.module.css'

/*
La tabla que sustituye al `<pre>` con el JSON en crudo.

Sólo cambia CÓMO se lee: no hay ni un control nuevo. Los dos botones de fila
—«RRSIG» y «Glue»— no llaman a ningún endpoint: despliegan campos que ya venían
en el mismo JSON (`dnssecRecords` y `glueRecords`) y que en el volcado de
upstream se leían igual de mal que el resto.
*/

// El mismo corte que en Zones: era 48 aquí y 64 allí, para el mismo control.
const CORTE = 64

function Valor({ e }: { e: Entrada }) {
  const [abierto, setAbierto] = useState(false)

  if (!e.largo || abierto) return <span className={styles.clave}>{e.valor}</span>

  return (
    <>
      <span className={styles.clave}>{e.valor.slice(0, CORTE)}…</span>{' '}
      <button type="button" className={styles.verlo} onClick={() => setAbierto(true)}>
        show full
      </button>
    </>
  )
}

function Kv({ entradas }: { entradas: Entrada[] }) {
  if (entradas.length === 0) return null
  return (
    <dl className={styles.kv}>
      {entradas.map((e) => (
        <div key={e.clave} style={{ display: 'contents' }}>
          <dt>{e.clave}</dt>
          <dd>
            <Valor e={e} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

function Fila({ r, conDnssec, nodo }: { r: RegistroDns; conDnssec: boolean; nodo: string }) {
  const [firmas, setFirmas] = useState(false)
  const [glue, setGlue] = useState(false)

  const ttl = ttlPartido(r)
  const nombre = r.nameIdn ?? r.name
  // El nombre coincide siempre con el nodo abierto; sólo se dice si NO coincide.
  const nombreDistinto = r.name !== nodo && nombre !== nodo

  return (
    <tr>
      <td>
        <Chip>{r.type}</Chip>
        {nombreDistinto && <span className={styles.nombre}>{nombre === '' ? '<ROOT>' : nombre}</span>}
      </td>
      <td className={styles.ttl}>
        {ttl.valor} {ttl.humano && <small>({ttl.humano})</small>}
      </td>
      <td>
        <Kv entradas={[...entradasRData(r.rData), ...extras(r)]} />
        <div className={styles.meta} title={r.lastUsedOn}>
          {meta(r).join(' · ')}
        </div>
        {firmas && r.dnssecRecords && (
          <pre className={styles.firmas}>{r.dnssecRecords.join('\n')}</pre>
        )}
        {glue && r.glueRecords && <pre className={styles.firmas}>{r.glueRecords.join('\n')}</pre>}
      </td>
      {conDnssec && (
        <td>
          <Tag tone={r.dnssecStatus === 'Secure' ? 'ok' : 'neutral'}>
            {r.dnssecStatus ?? '—'}
          </Tag>
        </td>
      )}
      <td className={tbl.celdaAcciones}>
        <div className={tbl.acciones}>
          {r.glueRecords && (
            <Button
              size="sm"
              aria-pressed={glue}
              onClick={() => setGlue((v) => !v)}
            >
              Glue
            </Button>
          )}
          {r.dnssecRecords && (
            <Button
              size="sm"
              aria-pressed={firmas}
              onClick={() => setFirmas((v) => !v)}
            >
              RRSIG
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}

export function Registros({
  records,
  conDnssec,
  nodo,
}: {
  records: RegistroDns[]
  /** La columna DNSSEC es sólo de Cache; en el resto baja a la línea gris. */
  conDnssec: boolean
  nodo: string
}) {
  return (
    <div className={tbl.wrap}>
      <table className={tbl.tabla}>
        <thead>
          <tr>
            <th style={{ width: 110 }}>Type</th>
            <th style={{ width: 120 }}>TTL</th>
            <th>Data</th>
            {conDnssec && <th style={{ width: 100 }}>DNSSEC</th>}
            <th style={{ width: 120 }}>
              <span className="sr-only" />
            </th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => (
            <Fila key={`${r.name}|${r.type}|${i}`} r={r} conDnssec={conDnssec} nodo={nodo} />
          ))}
        </tbody>
      </table>
    </div>
  )
}
