import { useState } from 'react'
import { getSettings, setSettings, temporaryDisableBlocking } from '../../api/settings'
import { Confirmar } from '../../ui/Confirmar'
import { Menu } from '../../ui/Menu'
import type { AlertType } from '../../ui/Alert'

/*
El menú «Blocking» del Dashboard.

Upstream lo pone en la cabecera de «Top Blocked Domains»
(`btnDashboardBlockingOptions`, index.html) y aquí no estaba: apagar el bloqueo
un rato desde el Dashboard es de las cosas que más se hacen en esta consola —lo
típico es que una página no cargue por culpa de una lista— y obligaba a irse a
Settings › Blocking a buscarlo.

Dos detalles de conducta que se copian tal cual:

- El estado se pregunta AL ABRIR el menú, no al pintar la pantalla
  (`main.js:2429`): entre una cosa y otra el ajuste puede haber cambiado desde
  otra pestaña, y enseñar «Enable Blocking» con el bloqueo ya encendido es peor
  que tardar 100 ms.
- Sale «Enable» o «Disable», nunca los dos. Mientras no se sabe, ninguno.

Los textos de confirmación y de aviso son los literales de upstream
(`main.js:2448-2496`). Lo que cambia es la forma de preguntar: allí es un
`confirm()` del navegador y aquí el diálogo de la consola.
*/

/** Los ocho plazos de upstream, con su rótulo exacto. */
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
  texto: string
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
  const [activo, setActivo] = useState<boolean | null>(null)
  const [pendiente, setPendiente] = useState<Pendiente | null>(null)
  const [ocupado, setOcupado] = useState(false)

  async function mirarEstado() {
    setActivo(null)
    const s = await getSettings(token)
    if (s != null) setActivo(s.enableBlocking)
  }

  function conmutar(encender: boolean): Pendiente {
    return {
      titulo: encender ? 'Enable Blocking' : 'Disable Blocking',
      texto: `Are you sure you want to ${encender ? 'enable' : 'disable'} blocking?`,
      etiqueta: encender ? 'Enable' : 'Disable',
      variante: encender ? 'primary' : 'danger',
      hacer: async () => {
        const r = await setSettings(token, { enableBlocking: String(encender) })
        if (r.kind !== 'ok') throw new Error(r.kind === 'error' ? r.message : 'Session expired.')
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
      texto: `Are you sure to temporarily disable blocking for ${minutos} minute(s)?`,
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
    setOcupado(true)
    try {
      await pendiente.hacer()
      setPendiente(null)
    } catch (e) {
      onAviso({ type: 'danger', title: 'Error!', text: (e as Error).message })
      setPendiente(null)
    } finally {
      setOcupado(false)
    }
  }

  return (
    <>
      <Menu etiqueta="Blocking options" rotulo="Blocking" onAbrir={() => void mirarEstado()}>
        {(cerrar) => (
          <>
            {activo === false && (
              <button role="menuitem" onClick={() => { cerrar(); setPendiente(conmutar(true)) }}>
                Enable Blocking
              </button>
            )}
            {activo === true && (
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
        texto={pendiente?.texto ?? ''}
        etiqueta={pendiente?.etiqueta ?? ''}
        variante={pendiente?.variante}
        ocupado={ocupado}
        onCerrar={() => setPendiente(null)}
        onConfirmar={() => void confirmar()}
      />
    </>
  )
}
