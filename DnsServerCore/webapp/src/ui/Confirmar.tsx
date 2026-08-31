import { useState, type ReactNode } from 'react'
import { Button } from './Button'
import { Dialog } from './Dialog'
import texto from './texto.module.css'

/*
El paso de «¿seguro?».

Upstream lo resuelve con `confirm()` nativo; el texto y el paso son los mismos,
porque sigue haciendo falta confirmar antes de que salga la petición.

Estaba escrito seis veces: una como componente dentro de Administration —de
donde lo importaban el Dashboard, Zones y Listas, que no tienen nada que ver con
Administration—, otra como componente dentro de Settings, y cuatro a pelo con
`Dialog` + un botón + `cerrar="Cancel"` + `tamano="compacto"` en Logs, DHCP y
otra vez Zones y Listas. Esta consola no tiene deshacer en ninguna parte, así
que el sitio donde menos conviene tener seis versiones es justo éste.

De las seis, dos —Zones y Listas— llevaban el «ocupado» y el cierre DENTRO del
diálogo, y las otras cuatro se lo pedían a cada sitio de llamada. La primera
forma es mejor y no hace falta una segunda API para tenerla: si `onConfirmar`
devuelve una promesa, este componente deshabilita el botón mientras dura y
cierra al acabar. Quien ya lleva su propio estado sigue pasando `ocupado`.

No cubre el diálogo de «Remove Lease?», y es a propósito: ése no es una
confirmación de una línea sino cuatro párrafos de advertencia con su lista de
alternativas y su hueco para un aviso del servidor. Que quepa en `texto` no lo
convierte en lo mismo.
*/
export function Confirmar({
  abierto,
  titulo,
  texto: cuerpo,
  etiqueta,
  variante = 'danger',
  ocupado,
  onCerrar,
  onConfirmar,
}: {
  abierto: boolean
  titulo: string
  texto: ReactNode
  /** El verbo de la acción: «Delete», «Convert», «Disable». */
  etiqueta: string
  variante?: 'primary' | 'danger'
  ocupado?: boolean
  onCerrar: () => void
  /** Si devuelve una promesa, el diálogo se ocupa mientras dura y cierra al acabar. */
  onConfirmar: () => unknown
}) {
  const [enCurso, setEnCurso] = useState(false)

  function confirmar() {
    const r = onConfirmar()
    if (!(r instanceof Promise)) return
    setEnCurso(true)
    void r.finally(() => {
      setEnCurso(false)
      onCerrar()
    })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={titulo}
      acciones={
        <Button variant={variante} disabled={ocupado || enCurso} onClick={confirmar}>
          {etiqueta}
        </Button>
      }
      cerrar="Cancel"
      tamano="compacto"
    >
      {/* `pre-wrap`: hay confirmaciones de varias líneas —las de Zones— y sin
          esto se leían como un párrafo corrido en una pantalla y no en otra. */}
      <div className={texto.parrafo} style={{ whiteSpace: 'pre-wrap' }}>
        {cuerpo}
      </div>
    </Dialog>
  )
}
