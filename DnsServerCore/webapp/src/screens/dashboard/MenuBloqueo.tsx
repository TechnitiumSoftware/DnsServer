import { useState } from 'react'
import { getSettings, setSettings, temporaryDisableBlocking } from '../../api/settings'
import { Confirmar } from '../../ui/Confirmar'
import { Menu } from '../../ui/Menu'
import type { AlertType } from '../../ui/Alert'
import { avisoDeFallo } from '../../lib/aviso'

/*
The Dashboard's "Blocking" menu.

Upstream puts it in the header of "Top Blocked Domains"
(`btnDashboardBlockingOptions`, index.html) and here it was missing: turning
blocking off for a while from the Dashboard is one of the things most often done
in this console —the typical case is a page not loading because of a list— and it
forced a trip to Settings › Blocking to find it.

Two behavioural details copied as they are:

- The state is asked for ON OPENING the menu, not when drawing the screen
  (`main.js:2429`): between the two the setting may have changed from another
  tab, and showing "Enable Blocking" with blocking already on is worse than
  taking 100 ms.
- Either "Enable" or "Disable" comes out, never both. While it is not known,
  neither.

The confirmation and alert texts are upstream's literals
(`main.js:2448-2496`). What changes is the way of asking: there it is a browser
`confirm()` and here the console's dialog.
*/

/** Upstream's eight durations, with their exact labels. */
const PLAZOS: { minutos: number; rotulo: string }[] = [
  { minutos: 1, rotulo: 'Disable Blocking For 1 Minute' },
  { minutos: 2, rotulo: 'Disable Blocking For 2 Minutes' },
  { minutos: 5, rotulo: 'Disable Blocking For 5 Minutes' },
  { minutos: 10, rotulo: 'Disable Blocking For 10 Minutes' },
  { minutos: 15, rotulo: 'Disable Blocking For 15 Minutes' },
  { minutos: 30, rotulo: 'Disable Blocking For 30 Minutes' },
  { minutos: 60, rotulo: 'Disable Blocking For 1 Hour' },
  { minutos: 180, rotulo: 'Disable Blocking For 3 Hours' },
]

interface Pendiente {
  titulo: string
  text: string
  etiqueta: string
  variante: 'primary' | 'danger'
  hacer: () => Promise<void>
}

export function MenuBloqueo({
  token,
  onAviso,
}: {
  token: string | null
  onAviso: (a: { type: AlertType; title: string; text: string }) => void
}) {
  const [active, setActivo] = useState<boolean | null>(null)
  const [pendiente, setPendiente] = useState<Pendiente | null>(null)
  const [busy, setBusy] = useState(false)

  async function mirarEstado() {
    setActivo(null)
    const s = await getSettings(token)
    if (s != null) setActivo(s.enableBlocking)
  }

  function conmutar(encender: boolean): Pendiente {
    return {
      titulo: encender ? 'Enable Blocking' : 'Disable Blocking',
      text: `Are you sure you want to ${encender ? 'enable' : 'disable'} blocking?`,
      etiqueta: encender ? 'Enable' : 'Disable',
      variante: encender ? 'primary' : 'danger',
      hacer: async () => {
        const r = await setSettings(token, { enableBlocking: String(encender) })
        // The same text as the other thirty-six: it was the only one that said
        // a bare "Session expired." for this very condition.
        if (r.kind !== 'ok') throw new Error(avisoDeFallo(r).text)
        setActivo(encender)
        onAviso({
          type: 'success',
          title: encender ? 'Blocking Enabled!' : 'Blocking Disabled!',
          text: `Blocking was ${encender ? 'enabled' : 'disabled'} successfully.`,
        })
      },
    }
  }

  function porUnRato(minutos: number): Pendiente {
    return {
      titulo: 'Temporarily Disable Blocking',
      text: `Are you sure to temporarily disable blocking for ${minutos} minute(s)?`,
      etiqueta: 'Disable',
      variante: 'danger',
      hacer: async () => {
        const till = await temporaryDisableBlocking(token, String(minutos))
        if (till == null) throw new Error('The request failed.')
        setActivo(false)
        onAviso({
          type: 'success',
          title: 'Blocking Disabled!',
          text: `Blocking was successfully disabled temporarily for ${minutos} minute(s).`,
        })
      },
    }
  }

  async function confirmar() {
    if (pendiente == null) return
    setBusy(true)
    try {
      await pendiente.hacer()
      setPendiente(null)
    } catch (e) {
      onAviso({ type: 'danger', title: 'Error!', text: (e as Error).message })
      setPendiente(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Menu etiqueta="Blocking options" rotulo="Blocking" onAbrir={() => void mirarEstado()}>
        {(cerrar) => (
          <>
            {active === false && (
              <button role="menuitem" onClick={() => { cerrar(); setPendiente(conmutar(true)) }}>
                Enable Blocking
              </button>
            )}
            {active === true && (
              <button role="menuitem" onClick={() => { cerrar(); setPendiente(conmutar(false)) }}>
                Disable Blocking
              </button>
            )}
            {PLAZOS.map((p) => (
              <button
                key={p.minutos}
                role="menuitem"
                onClick={() => { cerrar(); setPendiente(porUnRato(p.minutos)) }}
              >
                {p.rotulo}
              </button>
            ))}
          </>
        )}
      </Menu>

      <Confirmar
        abierto={pendiente != null}
        titulo={pendiente?.titulo ?? ''}
        text={pendiente?.text ?? ''}
        etiqueta={pendiente?.etiqueta ?? ''}
        variante={pendiente?.variante}
        busy={busy}
        onCerrar={() => setPendiente(null)}
        onConfirmar={() => void confirmar()}
      />
    </>
  )
}
