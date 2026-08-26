import type { ReactNode } from 'react'
import styles from './SectionHeader.module.css'

/*
La cabecera de una sección. Antes había cuatro tratamientos distintos:

  · 22 px en Zones, Cache, Allowed, Blocked, Apps, DHCP, Administration y Logs
  · 19 px en About
  · **14 px** en Settings, con el nombre del panel en un `span` apagado
  · **ninguno** en Dashboard y DNS Client

El de 14 px era el peor sitio para el título más pequeño: Settings es la
pantalla más larga de la consola (5.400 px de scroll, 54 campos) y la que puede
tirar el servidor. Y las nueve sub-pestañas mostraban el mismo «Settings», así
que el título no servía ni para saber dónde estabas ni para buscar con Ctrl+F.

## La composición

`seccion` es un ANTETÍTULO y sólo aparece cuando la sección tiene sub-pestañas:

    DHCP                 ← antetítulo, pequeño y apagado
    Leases               ← título, 22 px

Sin sub-pestañas no hay antetítulo y el título es el nombre de la sección a
secas. Así el título es siempre **el nombre más específico**, que es lo que hace
el dibujo en Administration y en Logs, y el antetítulo aporta el contexto que
allí faltaba sin caer en un «Logs Query Logs» redundante.

## Las etiquetas son ESTADO, no recuento

`etiquetas` está para píldoras de estado —`Primary`, `Enabled`, `DNSSEC`—. Los
recuentos tienen su sitio en la barra de recuento sobre la tabla; ponerlos aquí
con el mismo aspecto que un estado era otra de las incongruencias: la misma
píldora significaba unas veces un dato, otras un estado y otras un ajuste.
*/

export function SectionHeader({
  seccion,
  onVolver,
  titulo,
  etiquetas,
  acciones,
}: {
  /** Nombre de la sección. Sólo cuando hay sub-pestañas. */
  seccion?: string
  /** En una pantalla de detalle, la vuelta a la sección. El antetítulo pasa a
   *  ser ese camino: antes había un «← Zones» encima y un «ZONES» debajo, dos
   *  elementos diciendo lo mismo a dos centímetros de distancia. */
  onVolver?: () => void
  /** El nombre más específico: la sub-pestaña si la hay, si no la sección. */
  titulo: string
  /** Píldoras de ESTADO. Los recuentos van en la barra de recuento. */
  etiquetas?: ReactNode
  /** Barra de acciones, siempre arriba a la derecha. */
  acciones?: ReactNode
}) {
  return (
    <div className={styles.hrow}>
      <div className={styles.izq}>
        {seccion != null &&
          (onVolver != null ? (
            <button type="button" className={styles.volver} onClick={onVolver}>
              ← {seccion}
            </button>
          ) : (
            <div className={styles.antetitulo}>{seccion}</div>
          ))}
        <h1 className={styles.titulo}>{titulo}</h1>
        {etiquetas != null && <div className={styles.tags}>{etiquetas}</div>}
      </div>
      {acciones != null && <div className={styles.acts}>{acciones}</div>}
    </div>
  )
}
