import * as RadixDialog from '@radix-ui/react-dialog'
import type { ReactNode } from 'react'
import { Button } from './Button'
import { Icono } from './Icono'
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
  tamano = 'formulario',
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  /** Los botones que hacen algo. El de descartar no se pasa: lo pone Dialog. */
  acciones?: ReactNode
  /** Rótulo del botón de descartar. `Cancel` cuando el modal es una pregunta. */
  cerrar?: string
  /**
   * La talla, que la decide el CONTENIDO y no el gusto:
   *
   * · `compacto` — una pregunta y dos botones. El literal de confirmación más
   *   largo de la consola mide 405 px con la tipografía real, así que en 440
   *   caben todos en un renglón. Upstream no tiene esta talla porque sus
   *   confirmaciones son `confirm()` del navegador.
   * · `formulario` — campos con sus rótulos. Los que upstream deja en 600.
   * · `medio` — formularios largos y tablas estrechas. Los 750-800 de upstream.
   * · `ancho` — tablas de verdad. Los 940 de upstream.
   *
   * Los escalones son los de upstream, que sí decidía modal por modal; las
   * cifras son más bajas porque nuestra tipografía va más apretada.
   */
  tamano?: 'compacto' | 'formulario' | 'medio' | 'ancho'
}) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={styles.overlay} />
        <RadixDialog.Content
          className={`${styles.content} ${styles[tamano]}`}
          data-tamano={tamano}
        >
          <div className={styles.head}>
            <RadixDialog.Title className={styles.title}>{title}</RadixDialog.Title>
            <RadixDialog.Close className={styles.close} aria-label="Close">
              <Icono nombre="cerrar" tam={16} />
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
