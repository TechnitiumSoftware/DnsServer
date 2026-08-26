import { useEffect, useState } from 'react'
import { getTop, type Rango, type TipoTop, type TopEntry } from '../../api/dashboard'
import { Dialog } from '../../ui/Dialog'
import { Loading } from '../../ui/Empty'
import styles from './Dashboard.module.css'
import tbl from '../../ui/Table.module.css'

/*
`modalTopStats` (main.js:2879). Es lo que hay detrás de los tres botones «More»
del Dashboard: la lista larga —1000 entradas— del top que se estaba viendo
recortado a cinco.

Faltaba entero: los tres botones estaban puestos y no hacían nada. Lo destapó
el barrido de inventario de la fase 10.

El título lleva el límite dentro —«Top 1000 Clients»— y no es decorativo: dice
cuántas se han pedido, que es distinto de cuántas hay.

**Un cliente se pinta con más cosas que un dominio**: debajo del nombre va el
dominio que resolvió, y si el servidor lo estaba limitando la fila se marca y el
nombre lleva «(rate limited)» detrás. Los dos campos sólo vienen en `TopClients`.
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
  /** `null` con el modal cerrado. */
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
      /* Upstream le da 600 px (`modalTopStats`), no los 940 de las tablas anchas, y
         la medida le da la razón: la columna del dominio ocupaba 736 px para un
         texto de 148. Es una lista de dos columnas, no una tabla ancha. */
      tamano="formulario"
      title={tipo == null ? 'Top Stats' : `Top ${LIMITE} ${TITULOS[tipo]}`}
    >
      {cargando ? (
        <Loading compacto />
      ) : (
        <div className={styles.topTablaWrap}>
          <table className={styles.topTabla}>
            <thead>
              <tr>
                <th>{tipo == null ? '' : CABECERA[tipo]}</th>
                <th style={{ width: 110 }}>{tipo == null ? '' : CONTEO[tipo]}</th>
              </tr>
            </thead>
            <tbody>
              {filas.length === 0 ? (
                <tr>
                  <td colSpan={2} className={tbl.sinFilas}>
                    No Data
                  </td>
                </tr>
              ) : (
                filas.map((f, i) => (
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
                ))
              )}
            </tbody>
            <tfoot>
              <tr>
                <th colSpan={2}>
                  {tipo == null ? '' : `Total ${TITULOS[tipo]}: ${filas.length.toLocaleString()}`}
                </th>
              </tr>
            </tfoot>
          </table>
        </div>
      )}
    </Dialog>
  )
}
