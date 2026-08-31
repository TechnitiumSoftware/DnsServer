import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { openDownload } from '../../api/user'
import {
  flushCache,
  forceUpdateBlockLists,
  getSettings,
  backupParams,
  restoreSettings,
  initialBackupSelection,
  setSettings,
  temporaryDisableBlocking,
  type DnsSettings,
} from '../../api/settings'
import { buildBody, formularioDesdeAjustes, enabled, type SettingsForm } from './model'
import { General } from './panes/General'
import { WebService } from './panes/WebService'
import { OptionalProtocols } from './panes/OptionalProtocols'
import { Tsig } from './panes/Tsig'
import { Recursion } from './panes/Recursion'
import { Cache } from './panes/Cache'
import { Blocking } from './panes/Blocking'
import { ProxyForwarders } from './panes/ProxyForwarders'
import { Logging } from './panes/Logging'
import { BackupDialog, Confirm, RestoreDialog } from './dialogs'
import { Failure, Loading } from '../../ui/Empty'
import styles from './Settings.module.css'
import formulario from '../../ui/PanelForm.module.css'
import { noticeFromFailure, type Notice } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

/*
Settings. The console's biggest screen: in upstream, the General sub-tab alone is
5,452 px tall.

The sub-navigation is NOT mounted here. The nine sub-tabs live in the Shell's
side panel, nested under Settings, and arrive through the `sub` prop. This
component only decides which panel it draws and keeps A SINGLE form state for the
nine: upstream does not have nine forms either, it has one with nine tabs, and
"Save Settings" ALWAYS sends the fields of all nine wherever you are. Chopping it
up per tab would change what gets saved.

Two consequences of that to keep in mind:

  · A validation failure can be on another sub-tab. Upstream focuses the field
    even when its tab is hidden and the user sees nothing. Here the alert says
    what is missing and the screen jumps to the field's sub-tab.
  · The three permissions on the bar are different: saving requires
    `Settings.canModify`, flushing the cache `Cache.canDelete`, and backup and
    restore `Settings.canDelete` (main.js:906-930).
*/

export const SUB_TABS = [
  'General',
  'Web Service',
  'Optional Protocols',
  'TSIG',
  'Recursion',
  'Cache',
  'Blocking',
  'Proxy & Forwarders',
  'Logging',
] as const

export type SubTab = (typeof SUB_TABS)[number]


export interface SettingsProps {
  token: string | null
  /** The active sub-tab, the one the Shell's side panel marks. */
  sub?: string | null
  /** Lets the Shell follow the screen when a validation failure forces it to
   *  jump to another sub-tab. */
  onSubChange?: (sub: SubTab) => void
  canModify?: boolean
  canFlushCache?: boolean
  canBackup?: boolean
}

export function Settings({
  token,
  sub,
  onSubChange,
  canModify = true,
  canFlushCache = true,
  canBackup = true,
}: SettingsProps) {
  const [settings, setAjustes] = useState<DnsSettings | null>(null)
  const [form, setForm] = useState<SettingsForm | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  // The validation jump remembers which sub-tab it fired from: as soon as the
  // Shell asks for a different one, it stops holding. Deriving it this way avoids
  // an effect whose only job was to null it out, and the extra render it brings.
  const [newline, setSalto] = useState<{ tab: SubTab; since2: string } | null>(null)
  const [confirm, setConfirm] = useState<null | 'flush' | 'disable' | 'update'>(null)
  const [modal, setModal] = useState<null | 'backup' | 'restore'>(null)
  const [selection, setSelection] = useState<Record<string, boolean>>(initialBackupSelection)
  const [modalNotice, setModalNotice] = useState<{ title: string; text: string } | null>(null)
  const [nextList, setNextList] = useState<string | null | undefined>(undefined)

  const load = useCallback(async () => {
    setLoading(true)
    const s = await getSettings(token)
    apply(s)
    setLoading(false)
  }, [token])

  function apply(s: DnsSettings | null) {
    setAjustes(s)
    setForm(s ? formularioDesdeAjustes(s) : null)
    setNextList(s?.blockListNextUpdatedOn)
  }

  useEffect(() => {
    void load()
  }, [load])

  const requested = (sub ?? 'General') as SubTab
  const valid: SubTab = SUB_TABS.includes(requested) ? requested : 'General'
  const active: SubTab = newline?.since2 === valid ? newline.tab : valid

  const set = useCallback((partial: Partial<SettingsForm>) => {
    setForm((f) => (f ? { ...f, ...partial } : f))
  }, [])

  if (loading) return <Loading />
  if (form == null || settings == null) {
    return <Failure>Unable to load the DNS Server settings.</Failure>
  }

  const en = enabled(form)

  async function save() {
    if (form == null) return
    const result = buildBody(form)

    if (result.error) {
      const { title, text, tab } = result.error
      setNotice({ type: 'warning', title, text })
      const target = tab as SubTab
      setSalto({ tab: target, since2: valid })
      onSubChange?.(target)
      return
    }

    setBusy(true)
    const outcome = await setSettings(token, result.body!)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    apply(outcome.data.response)
    setNotice({
      type: 'success',
      title: 'Settings Saved!',
      text: 'DNS Server settings were saved successfully.',
    })
  }

  async function doFlushCache() {
    setConfirm(null)
    setBusy(true)
    const ok = await flushCache(token)
    setBusy(false)
    if (ok) {
      setNotice({
        type: 'success',
        title: 'Flushed!',
        text: 'DNS Server cache was flushed successfully.',
      })
    }
  }

  function askDisableBlocking() {
    if (form == null) return
    if (form.temporaryDisableBlockingMinutes === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text: 'Please enter a value in minutes to temporarily disable blocking.',
      })
      return
    }
    setConfirm('disable')
  }

  async function disableBlocking() {
    if (form == null) return
    const minutes = form.temporaryDisableBlockingMinutes
    setConfirm(null)
    setBusy(true)
    const till = await temporaryDisableBlocking(token, minutes)
    setBusy(false)
    if (till == null) return

    setAjustes((a) => (a ? { ...a, temporaryDisableBlockingTill: till } : a))
    set({ enableBlocking: false })
    setNotice({
      type: 'success',
      title: 'Blocking Disabled!',
      text: `Blocking was successfully disabled temporarily for ${minutes} minute(s).`,
    })
  }

  async function updateLists() {
    setConfirm(null)
    setBusy(true)
    const ok = await forceUpdateBlockLists(token)
    setBusy(false)
    if (!ok) return
    // main.js:2356 — the label becomes "Updating Now" without reloading the settings.
    setNextList(new Date(0).toISOString())
    setNotice({
      type: 'success',
      title: 'Updating Block List!',
      text: 'Block list update was triggered successfully.',
    })
  }

  async function hacerBackup() {
    if (!Object.values(selection).some(Boolean)) {
      setModalNotice({ title: 'Missing!', text: 'Please select at least one item to backup.' })
      return
    }
    setModalNotice(null)
    setBusy(true)
    const r = await openDownload(token, 'settings/backup', backupParams(selection), { ts: true })
    setBusy(false)
    if (!r.ok) return
    setModal(null)
    setNotice({
      type: 'success',
      title: 'Backed Up!',
      text: 'Settings were backed up successfully.',
    })
  }

  async function hacerRestore(file: File | null, remove: boolean) {
    // The validation order is upstream's: the file first, then that there is
    // at least one item checked (main.js:3137-3160).
    if (file == null) {
      setModalNotice({ title: 'Missing!', text: 'Please select a backup zip file to restore.' })
      return
    }
    if (!Object.values(selection).some(Boolean)) {
      setModalNotice({ title: 'Missing!', text: 'Please select at least one item to restore.' })
      return
    }
    setModalNotice(null)
    setBusy(true)
    const outcome = await restoreSettings(token, file, selection, remove)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setModalNotice(noticeFromFailure(outcome))
      return
    }

    apply(outcome.data.response)
    setModal(null)
    setNotice({
      type: 'success',
      title: 'Restored!',
      text: 'Settings were restored successfully.',
    })
  }

  const props = { f: form, set, en }

  return (
    <div className={styles.wrap}>
      {/* The title is the sub-tab, not "Settings": all nine said the same
          thing, so it was no use either for orienting yourself or for finding it
          with Ctrl+F. */}
      <SectionHeader section="Settings" title={active} />

      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div>
        {active === 'General' && <General {...props} />}
        {active === 'Web Service' && <WebService {...props} />}
        {active === 'Optional Protocols' && <OptionalProtocols {...props} />}
        {active === 'TSIG' && <Tsig {...props} />}
        {active === 'Recursion' && <Recursion {...props} />}
        {active === 'Cache' && <Cache {...props} />}
        {active === 'Blocking' && (
          <Blocking
            {...props}
            extra={{
              temporaryDisableBlockingTill: settings.temporaryDisableBlockingTill,
              blockListNextUpdatedOn: nextList,
              onTemporaryDisable: askDisableBlocking,
              onUpdateNow: () => setConfirm('update'),
              busy,
            }}
          />
        )}
        {active === 'Proxy & Forwarders' && <ProxyForwarders {...props} />}
        {active === 'Logging' && <Logging {...props} />}
      </div>

      <div className={formulario.bar}>
        {canModify && (
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save Settings
          </Button>
        )}
        {canFlushCache && (
          <Button variant="danger" disabled={busy} onClick={() => setConfirm('flush')}>
            Flush Cache
          </Button>
        )}
        <div className={formulario.spacer} />
        {canBackup && (
          <>
            <Button
              onClick={() => {
                setSelection(initialBackupSelection())
                setModalNotice(null)
                setModal('backup')
              }}
            >
              Backup Settings
            </Button>
            <Button
              onClick={() => {
                setSelection(initialBackupSelection())
                setModalNotice(null)
                setModal('restore')
              }}
            >
              Restore Settings
            </Button>
          </>
        )}
      </div>

      <Confirm
        open={confirm === 'flush'}
        onClose={() => setConfirm(null)}
        title="Flush Cache"
        label="Flush"
        variant="primary"
        text="Are you sure to flush the DNS Server cache?"
        busy={busy}
        onConfirm={() => void doFlushCache()}
      />
      <Confirm
        open={confirm === 'disable'}
        onClose={() => setConfirm(null)}
        title="Temporary Disable Blocking"
        label="Disable"
        variant="primary"
        text={`Are you sure to temporarily disable blocking for ${form.temporaryDisableBlockingMinutes} minute(s)?`}
        busy={busy}
        onConfirm={() => void disableBlocking()}
      />
      <Confirm
        open={confirm === 'update'}
        onClose={() => setConfirm(null)}
        title="Update Block Lists"
        label="Update"
        variant="primary"
        text="Are you sure to force download and update the block lists?"
        busy={busy}
        onConfirm={() => void updateLists()}
      />

      <BackupDialog
        open={modal === 'backup'}
        onOpenChange={(o) => setModal(o ? 'backup' : null)}
        selection={selection}
        onSelection={setSelection}
        notice={modalNotice}
        busy={busy}
        onBackup={() => void hacerBackup()}
      />
      <RestoreDialog
        open={modal === 'restore'}
        onOpenChange={(o) => setModal(o ? 'restore' : null)}
        selection={selection}
        onSelection={setSelection}
        notice={modalNotice}
        busy={busy}
        onRestore={(file, remove) => void hacerRestore(file, remove)}
      />
    </div>
  )
}
