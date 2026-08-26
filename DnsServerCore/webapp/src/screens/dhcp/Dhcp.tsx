import { Leases } from './Leases'
import { Scopes } from './Scopes'

/*
DHCP. Dos sub-pestañas, con las etiquetas literales de upstream
(index.html:2496-2497): «Leases» y «Scopes».

La sub-navegación NO se monta aquí: vive en el panel lateral del Shell, igual
que la de Settings, y llega por la prop `sub`. A diferencia de Settings, las dos
sub-pestañas son pantallas independientes —cada una con su propia carga y su
propio estado—, así que sí se pueden trocear: en upstream son dos funciones
distintas, `refreshDhcpLeases` y `refreshDhcpScopes`, y no comparten formulario.

El selector de nodo del clúster de upstream (`optDhcpClusterNode`) no se monta:
esta consola aún no tiene modo clúster. El parámetro `node` viaja igual, vacío,
en las diez llamadas, que es lo que manda upstream con un solo servidor.
*/

export const SUBPESTANAS = ['Leases', 'Scopes'] as const
export type Subpestana = (typeof SUBPESTANAS)[number]

export interface DhcpProps {
  token: string | null
  /** Sub-pestaña activa, la que marca el panel lateral del Shell. */
  sub?: string | null
  /** Existe por simetría con Settings; esta pantalla nunca fuerza un cambio. */
  onSubChange?: (sub: Subpestana) => void
  /** `DhcpServer.canModify`: guardar un scope, habilitarlo, deshabilitarlo y
   *  convertir una concesión (`WebServiceDhcpApi.cs:379,708,733,805,835`). */
  canModify?: boolean
  /** `DhcpServer.canDelete`: borrar un scope y quitar una concesión
   *  (`WebServiceDhcpApi.cs:761,775`). Ojo: NO es `canModify`. */
  canDelete?: boolean
  /** Nodo del clúster. Vacío significa «este servidor». */
  node?: string
}

export function Dhcp({
  token,
  sub,
  canModify = true,
  canDelete = true,
  node = '',
}: DhcpProps) {
  const pedida = (sub ?? 'Leases') as Subpestana
  const activa: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'Leases'

  return activa === 'Scopes' ? (
    <Scopes token={token} node={node} canModify={canModify} canDelete={canDelete} />
  ) : (
    <Leases token={token} node={node} canModify={canModify} canDelete={canDelete} />
  )
}
