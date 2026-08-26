import { useCallback, useEffect, useState } from 'react'
import { getClusterState, type ClusterState } from '../../api/admin-cluster'
import { Sessions } from './Sessions'
import { Users } from './Users'
import { Groups } from './Groups'
import { Permissions } from './Permissions'
import { Sso } from './Sso'
import { Cluster } from './Cluster'
import { Avisador, type Aviso } from './partes'

/*
Administration. Seis sub-pestañas y treinta endpoints: el segundo bloque más
grande de la consola después de Zones.

La sub-navegación NO se monta aquí. Igual que en Settings, las sub-pestañas
viven en el panel lateral del Shell y llegan por la prop `sub`. Este componente
sólo decide qué panel pinta y sostiene las dos cosas que las seis comparten: el
aviso de página y el estado del cluster.

Sobre los permisos, y va contra la intuición: **upstream NO oculta ni deshabilita
NADA dentro de Administration**. La única comprobación que hace es
`permissions.Administration.canView` para enseñar o esconder la sección entera
(main.js:165 y 240), y a partir de ahí muestra todos los botones y deja que el
servidor rechace lo que no toque. Por eso este componente no recibe props de
permiso: añadirlas sería añadir comportamiento. Los permisos que consume cada
acción están anotados en `src/api/admin.ts` y `src/api/admin-cluster.ts`.

Sobre el cluster: upstream lee `clusterInitialized` y `clusterNodes` de
`sessionData.info`, que llega en el login. La sesión que reparte el Shell no los
expone, así que aquí se piden una vez con `admin/cluster/state` —el mismo dato,
y permitido con el mismo `canView` que hace falta para ver la sección— y se
comparten con las seis sub-pestañas. La sub-pestaña Cluster lo refresca cada vez
que cambia, igual que hace `reloadAdminClusterView`.
*/

export const SUBPESTANAS = ['Sessions', 'Users', 'Groups', 'Permissions', 'SSO', 'Cluster'] as const

export type Subpestana = (typeof SUBPESTANAS)[number]

export interface AdminProps {
  token: string | null
  /** Sub-pestaña activa, la que marca el panel lateral del Shell. */
  sub?: string | null
  /** Presente por simetría con Settings; Administration nunca cambia de
   *  sub-pestaña por su cuenta, así que hoy no se invoca. */
  onSubChange?: (sub: Subpestana) => void
}

export function Admin({ token, sub }: AdminProps) {
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cluster, setCluster] = useState<ClusterState | null>(null)

  useEffect(() => {
    let vivo = true
    void getClusterState(token).then((outcome) => {
      if (vivo && outcome.kind === 'ok') setCluster(outcome.data.response)
    })
    return () => {
      vivo = false
    }
  }, [token])

  // Estable entre renders: las sub-pestañas la meten en las dependencias de su
  // `useCallback` de carga, y una función nueva por render las recargaría en
  // bucle.
  const avisar = useCallback((a: Aviso) => setAviso(a), [])
  const alCluster = useCallback((s: ClusterState) => setCluster(s), [])

  const pedida = (sub ?? 'Sessions') as Subpestana
  const activa: Subpestana = SUBPESTANAS.includes(pedida) ? pedida : 'Sessions'

  return (
    <div>
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {activa === 'Sessions' && <Sessions token={token} cluster={cluster} onAviso={avisar} />}
      {activa === 'Users' && <Users token={token} cluster={cluster} onAviso={avisar} />}
      {activa === 'Groups' && <Groups token={token} onAviso={avisar} />}
      {activa === 'Permissions' && (
        <Permissions token={token} cluster={cluster} onAviso={avisar} />
      )}
      {activa === 'SSO' && <Sso token={token} onAviso={avisar} />}
      {activa === 'Cluster' && (
        <Cluster token={token} cluster={cluster} onCluster={alCluster} onAviso={avisar} />
      )}
    </div>
  )
}
