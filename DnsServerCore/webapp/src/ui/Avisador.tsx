import { Alert } from './Alert'
import type { Aviso } from '../lib/aviso'
import styles from './Alert.module.css'

/*
El hueco del aviso de una pantalla o de un modal: si hay aviso, se pinta; si no,
no hay nada. Y siempre con el mismo aire debajo.

Existía como componente dentro de Administration y lo usaba UNA pantalla; las
otras cincuenta escribían el mismo `{aviso && (<Alert …>{aviso.text}</Alert>)}` a
mano. De ahí salieron tres distancias distintas para lo mismo, medidas en el
navegador forzando un fallo del servidor:

  · 24 px en Zones, sus doce modales, Listas, Administration, Dashboard, DNS
    Client y Apps, que envolvían el aviso en un `div` con margen;
  · 14 px en DHCP y en Logs, donde el aviso iba suelto dentro del contenedor
    `flex` de la pantalla y se quedaba con su `gap`;
  · 12 px en los cuatro modales de cuenta, por lo mismo dentro del diálogo.

Se queda en 24, que es `--hueco-bloque` —el token que nombra la distancia entre
bloques independientes— y el que ya tenían las tres cuartas partes.
*/
export function Avisador({ aviso, onCerrar }: { aviso: Aviso | null; onCerrar: () => void }) {
  if (aviso == null) return null
  return (
    <div className={styles.hueco}>
      <Alert type={aviso.type} title={aviso.title} onDismiss={onCerrar}>
        {aviso.text}
      </Alert>
    </div>
  )
}
