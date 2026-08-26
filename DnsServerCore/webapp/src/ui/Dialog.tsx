import * as RadixDialog from '@radix-ui/react-dialog'
import type { ReactNode } from 'react'
import { Button } from './Button'
import styles from './Dialog.module.css'

/*
El pie NO es texto libre. Cuando lo era, 23 modales ponían la acción primero y
17 la ponían última, y en cinco de ellos la acción era destructiva: `Delete` y
`Close` intercambiaban de sitio entre dos diálogos de la misma pantalla.

Aquí el orden es del componente, no de quien lo usa:

    [ acciones … ] [ Close ]

`acciones` son los botones que HACEN algo; el de descartar lo pinta `Dialog` y
va siempre el último, en la esquina donde upstream lo tenía en sus 40 modales.
Así ningún modal nuevo puede volver a elegir su propio orden.
*/

export function Dialog({
  open,
  onOpenChange,
  title,
  children,
  acciones,
  cerrar = 'Close',
  ancho = false,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  /** Los botones que hacen algo. El de descartar no se pasa: lo pone Dialog. */
  acciones?: ReactNode
  /** Rótulo del botón de descartar. `Cancel` cuando el modal es una pregunta. */
  cerrar?: string
  /** Los modales con tabla dentro necesitan más de los 560 px por defecto. */
  ancho?: boolean
}) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={styles.overlay} />
        <RadixDialog.Content className={`${styles.content}${ancho ? ` ${styles.ancho}` : ''}`}>
          <div className={styles.head}>
            <RadixDialog.Title className={styles.title}>{title}</RadixDialog.Title>
            <RadixDialog.Close className={styles.close} aria-label="Close">
              ✕
            </RadixDialog.Close>
          </div>
          <div className={styles.body}>{children}</div>
          <div className={styles.foot}>
            {acciones}
            <Button onClick={() => onOpenChange(false)}>{cerrar}</Button>
          </div>
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  )
}
