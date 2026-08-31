import { useState } from 'react'
import { getSettings, setSettings, temporaryDisableBlocking } from '../../api/settings'
import { Confirm } from '../../ui/Confirm'
import { Menu } from '../../ui/Menu'
import type { AlertType } from '../../ui/Alert'
import { noticeFromFailure } from '../../lib/notice'

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
const DURATIONS: { minutes: number; rotulo: string }[] = [
  { minutes: 1, rotulo: 'Disable Blocking For 1 Minute' },
  { minutes: 2, rotulo: 'Disable Blocking For 2 Minutes' },
  { minutes: 5, rotulo: 'Disable Blocking For 5 Minutes' },
  { minutes: 10, rotulo: 'Disable Blocking For 10 Minutes' },
  { minutes: 15, rotulo: 'Disable Blocking For 15 Minutes' },
  { minutes: 30, rotulo: 'Disable Blocking For 30 Minutes' },
  { minutes: 60, rotulo: 'Disable Blocking For 1 Hour' },
  { minutes: 180, rotulo: 'Disable Blocking For 3 Hours' },
]

interface Pending {
  title: string
  text: string
  label: string
  variant: 'primary' | 'danger'
  perform: () => Promise<void>
}

export function BlockingMenu({
  token,
  onNotice,
}: {
  token: string | null
  onNotice: (a: { type: AlertType; title: string; text: string }) => void
}) {
  const [active, setActive] = useState<boolean | null>(null)
  const [pending, setPendiente] = useState<Pending | null>(null)
  const [busy, setBusy] = useState(false)

  async function mirarEstado() {
    setActive(null)
    const s = await getSettings(token)
    if (s != null) setActive(s.enableBlocking)
  }

  function flip(turnOn: boolean): Pending {
    return {
      title: turnOn ? 'Enable Blocking' : 'Disable Blocking',
      text: `Are you sure you want to ${turnOn ? 'enable' : 'disable'} blocking?`,
      label: turnOn ? 'Enable' : 'Disable',
      variant: turnOn ? 'primary' : 'danger',
      perform: async () => {
        const r = await setSettings(token, { enableBlocking: String(turnOn) })
        // The same text as the other thirty-six: it was the only one that said
        // a bare "Session expired." for this very condition.
        if (r.kind !== 'ok') throw new Error(noticeFromFailure(r).text)
        setActive(turnOn)
        onNotice({
          type: 'success',
          title: turnOn ? 'Blocking Enabled!' : 'Blocking Disabled!',
          text: `Blocking was ${turnOn ? 'enabled' : 'disabled'} successfully.`,
        })
      },
    }
  }

  function forAWhile(minutes: number): Pending {
    return {
      title: 'Temporarily Disable Blocking',
      text: `Are you sure to temporarily disable blocking for ${minutes} minute(s)?`,
      label: 'Disable',
      variant: 'danger',
      perform: async () => {
        const till = await temporaryDisableBlocking(token, String(minutes))
        if (till == null) throw new Error('The request failed.')
        setActive(false)
        onNotice({
          type: 'success',
          title: 'Blocking Disabled!',
          text: `Blocking was successfully disabled temporarily for ${minutes} minute(s).`,
        })
      },
    }
  }

  async function confirm() {
    if (pending == null) return
    setBusy(true)
    try {
      await pending.perform()
      setPendiente(null)
    } catch (e) {
      onNotice({ type: 'danger', title: 'Error!', text: (e as Error).message })
      setPendiente(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Menu label="Blocking options" rotulo="Blocking" onOpen={() => void mirarEstado()}>
        {(close) => (
          <>
            {active === false && (
              <button role="menuitem" onClick={() => { close(); setPendiente(flip(true)) }}>
                Enable Blocking
              </button>
            )}
            {active === true && (
              <button role="menuitem" onClick={() => { close(); setPendiente(flip(false)) }}>
                Disable Blocking
              </button>
            )}
            {DURATIONS.map((p) => (
              <button
                key={p.minutes}
                role="menuitem"
                onClick={() => { close(); setPendiente(forAWhile(p.minutes)) }}
              >
                {p.rotulo}
              </button>
            ))}
          </>
        )}
      </Menu>

      <Confirm
        open={pending != null}
        title={pending?.title ?? ''}
        text={pending?.text ?? ''}
        label={pending?.label ?? ''}
        variant={pending?.variant}
        busy={busy}
        onClose={() => setPendiente(null)}
        onConfirm={() => void confirm()}
      />
    </>
  )
}
