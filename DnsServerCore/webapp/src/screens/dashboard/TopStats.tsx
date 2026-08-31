import { useEffect, useState } from 'react'
import { getTop, type Rango, type TipoTop, type TopEntry } from '../../api/dashboard'
import { Dialog } from '../../ui/Dialog'
import { Tabla } from '../../ui/Table'
import { Loading } from '../../ui/Empty'
import styles from './Dashboard.module.css'

/*
`modalTopStats` (main.js:2879). It is what sits behind the Dashboard's three
"More" buttons: the long list —1000 entries— of the top that was being seen
trimmed to five.

It was missing entirely: the three buttons were in place and did nothing. The
phase 10 inventory sweep uncovered it.

The title carries the limit inside it —"Top 1000 Clients"— and that is not
decorative: it says how many were asked for, which is different from how many
there are.

**A client is drawn with more things than a domain**: under the name goes the
domain it resolved, and if the server was rate-limiting it the row is marked and
the name carries "(rate limited)" after it. Both fields only come in
`TopClients`.
*/

const LIMITE = 1000

const TITULOS: Record<TipoTop, string> = {
  TopClients: 'Clients',
  TopDomains: 'Domains',
  TopBlockedDomains: 'Blocked Domains',
}

const CABECERA: Record<TipoTop, string> = {
  TopClients: 'Client',
  TopDomains: 'Domain',
  TopBlockedDomains: 'Domain',
}

const CONTEO: Record<TipoTop, string> = {
  TopClients: 'Queries',
  TopDomains: 'Hits',
  TopBlockedDomains: 'Hits',
}

export function TopStats({
  tipo,
  rango,
  token,
  onCerrar,
}: {
  /** `null` with the modal closed. */
  tipo: TipoTop | null
  rango: Rango
  token: string | null
  onCerrar: () => void
}) {
  const [filas, setFilas] = useState<TopEntry[]>([])
  const [cargando, setCargando] = useState(false)

  useEffect(() => {
    if (tipo == null) return
    setCargando(true)
    setFilas([])
    void getTop(token, rango, tipo, LIMITE).then((r) => {
      setFilas(r)
      setCargando(false)
    })
  }, [tipo, rango, token])

  const esCliente = tipo === 'TopClients'

  return (
    <Dialog
      open={tipo !== null}
      onOpenChange={(o) => !o && onCerrar()}
      /* Upstream gives it 600 px (`modalTopStats`), not the 940 of the wide
         tables, and the measurement proves it right: the domain column took 736 px
         for a text of 148. It is a two-column list, not a wide table. */
      tamano="formulario"
      title={tipo == null ? 'Top Stats' : `Top ${LIMITE} ${TITULOS[tipo]}`}
    >
      {cargando ? (
        <Loading compacto />
      ) : (
        <Tabla
          className={styles.topTablaWrap}
          claseTabla={styles.topTabla}
          cabecera={
            <>
              <th>{tipo == null ? '' : CABECERA[tipo]}</th>
              <th style={{ width: 110 }}>{tipo == null ? '' : CONTEO[tipo]}</th>
            </>
          }
          vacia={filas.length === 0}
          vacio="No Data"
          columnas={2}
          pie={
            <th colSpan={2}>
              {tipo == null ? '' : `Total ${TITULOS[tipo]}: ${filas.length.toLocaleString()}`}
            </th>
          }
        >
          {filas.map((f, i) => (
            <tr key={`${f.name}|${i}`} className={f.rateLimited ? styles.limitada : undefined}>
              <td>
                <span className={styles.topNombre}>
                  {f.name}
                  {f.rateLimited ? ' (rate limited)' : ''}
                </span>
                {esCliente && (
                  <span className={styles.topDominio}>
                    {f.domain === '' || f.domain == null ? '.' : f.domain}
                  </span>
                )}
              </td>
              <td className={styles.topConteo}>{f.hits.toLocaleString()}</td>
            </tr>
          ))}
        </Tabla>
      )}
    </Dialog>
  )
}
