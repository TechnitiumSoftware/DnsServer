import { useState, type ReactNode } from 'react'
import { Button } from './Button'
import { Dialog } from './Dialog'
import texto from './texto.module.css'

/*
The "are you sure?" step.

Upstream solves it with a native `confirm()`; the text and the step are the same,
because you still need to confirm before the request goes out.

It was written six times: once as a component inside Administration —from where
the Dashboard, Zones and the lists screens imported it, none of which have
anything to do with Administration— another as a component inside Settings, and
four times bare with `Dialog` + one button + `cerrar="Cancel"` +
`tamano="compacto"` in Logs, DHCP and again Zones and the lists. This console has
no undo anywhere, so the place where six versions are least welcome is precisely
this one.

Of the six, two —Zones and the lists— kept the "busy" flag and the closing INSIDE
the dialog, and the other four asked each call site for them. The first form is
better and no second API is needed to have it: if `onConfirmar` returns a promise,
this component disables the button while it runs and closes when it settles.
Whoever already tracks their own state keeps passing `ocupado`.

It does not cover the "Remove Lease?" dialog, and that is deliberate: that one is
not a one-line confirmation but four paragraphs of warning with its list of
alternatives and its slot for a server alert. That it would fit in `texto` does
not make it the same thing.
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
  /** The action's verb: "Delete", "Convert", "Disable". */
  etiqueta: string
  variante?: 'primary' | 'danger'
  ocupado?: boolean
  onCerrar: () => void
  /** If it returns a promise, the dialog stays busy while it runs and closes when it settles. */
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
      {/* `pre-wrap`: there are multi-line confirmations —the Zones ones— and
          without this they read as one run-on paragraph on one screen and not on
          another. */}
      <div className={texto.parrafo} style={{ whiteSpace: 'pre-wrap' }}>
        {cuerpo}
      </div>
    </Dialog>
  )
}
