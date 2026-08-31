import { useId, type ReactNode } from 'react'
import frm from './Form.module.css'

/*
La fila de un formulario: etiqueta a la izquierda, control a la derecha.

Estaba escrita a mano 38 veces, y además existía DOS veces como componente —en
`screens/settings/parts.tsx` y en `screens/dhcp/parts.tsx`, idénticas byte a
byte salvo un comentario—, sin que ninguna de las otras doce pantallas usara
ninguna de las dos. Con la fila suelta se fueron separando también las piezas
que la acompañan: la ayuda bajo el campo y el grupo de casillas estaban
definidos tres veces cada uno.

`modal` cambia la rejilla: dentro de un diálogo hay menos sitio y menos filas,
así que la columna de la etiqueta es más estrecha y no lleva separador. Es la
única diferencia real entre las dos variantes, y por eso es un parámetro y no
otro componente.
*/
export function Row({
  label,
  help,
  modal = false,
  children,
}: {
  label: string
  help?: ReactNode
  modal?: boolean
  /** Recibe el `id` que hay que poner en el control, para que la etiqueta lo gobierne. */
  children: (id: string) => ReactNode
}) {
  const id = useId()
  return (
    <div className={modal ? frm.mrow : frm.row}>
      <label className={modal ? frm.mrowLabel : frm.rowLabel} htmlFor={id}>
        {label}
      </label>
      <div className={modal ? frm.mrowCtl : frm.rowCtl}>
        {children(id)}
        {help != null && <div className={frm.ayuda}>{help}</div>}
      </div>
    </div>
  )
}

/**
 * Fila cuya etiqueta no gobierna un control concreto —grupos de casillas y de
 * radios—: upstream usa ahí un `<label>` sin `for`, porque apuntar a uno de los
 * controles del grupo mentiría sobre a qué se refiere.
 */
export function GroupRow({
  label,
  help,
  modal = false,
  children,
}: {
  label: string
  help?: ReactNode
  modal?: boolean
  children: ReactNode
}) {
  return (
    <div className={modal ? frm.mrow : frm.row}>
      <div className={modal ? frm.mrowLabel : frm.rowLabel}>{label}</div>
      <div className={modal ? frm.mrowCtl : frm.rowCtl}>
        <div className={frm.grupo}>{children}</div>
        {help != null && <div className={frm.ayuda}>{help}</div>}
      </div>
    </div>
  )
}

/** La ayuda suelta, para cuando no cuelga de una fila. */
export function Ayuda({ children }: { children: ReactNode }) {
  return <div className={frm.ayuda}>{children}</div>
}
