import { useCallback, useEffect, useState } from 'react'
import {
  deleteAllLogs,
  deleteLog,
  downloadLogText,
  listLogFiles,
  openLogDownload,
  type LogFile,
} from '../../api/logs'
import { deleteAllStats } from '../../api/dashboard'
import { Confirm } from '../../ui/Confirm'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import {Empty, Loading} from '../../ui/Empty'
import styles from './Logs.module.css'
import { Body, Panel } from '../../ui/Panel'
import { noticeFromFailure, type Notice } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

/*
Logs › View Logs (logs.js:105-268).

Four things from upstream that govern this screen:

  1. **The three delete actions are NOT of the same section.** "delete all logs"
     and deleting a file ask for `Logs.Delete`; "delete all stats" deletes the
     Dashboard's statistics and asks for `Dashboard.Delete`
     (`WebServiceLogsApi.cs:107,123,135`). They sit together on the screen and
     they are different permissions.
  2. **"delete all stats" is ALWAYS offered; "delete all logs" only if there are
     files** (logs.js:119-127). With no files it says "No Log File Was Found".
  3. **The viewer asks for only 2 MB** and the "Download" button for the whole
     file; they are two different calls to the same endpoint.
  4. **A server error is drawn INSIDE the viewer**, formatted as JSON, instead of
     as an alert (logs.js:170-172). It is not an oversight: the endpoint returns
     text and the only way to show the error is in that same space.
*/


export interface ViewLogsProps {
  token: string | null
  node?: string
  /** `Logs.canDelete`: deleting a log and deleting them all. */
  canDeleteLogs?: boolean
  /** `Dashboard.canDelete`: deleting all the statistics. */
  canDeleteStats?: boolean
}

type Confirmation = 'log' | 'allLogs' | 'allStats'

export function ViewLogs({
  token,
  node = '',
  canDeleteLogs = true,
  canDeleteStats = true,
}: ViewLogsProps) {
  const [files, setFiles] = useState<LogFile[] | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [body, setCuerpo] = useState<string | null>(null)
  const [loadingBody, setLoadingBody] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState<Confirmation | null>(null)

  // A failure on load is not drawn as an empty list; see `dhcp/Leases`.
  const load = useCallback(async () => {
    const r = await listLogFiles(token, node)
    if (r.kind === 'ok') {
      setFiles(r.data)
      return
    }
    setFiles([])
    setNotice(noticeFromFailure(r))
  }, [token, node])

  useEffect(() => {
    void load()
  }, [load])

  async function view(fileName: string) {
    setOpen(fileName)
    setCuerpo(null)
    setLoadingBody(true)
    const text = await downloadLogText(token, fileName, node)
    setLoadingBody(false)
    setCuerpo(text)
  }

  async function download() {
    if (open == null) return
    setBusy(true)
    await openLogDownload(token, open, node)
    setBusy(false)
  }

  async function removeLogFile() {
    if (open == null) return
    setConfirm(null)
    setBusy(true)
    const outcome = await deleteLog(token, open, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return

    await load()
    setOpen(null)
    setCuerpo(null)
    setNotice({
      type: 'success',
      title: 'Log Deleted!',
      text: 'Log file was deleted successfully.',
    })
  }

  async function removeAllLogs() {
    setConfirm(null)
    setBusy(true)
    const outcome = await deleteAllLogs(token, node)
    setBusy(false)
    if (outcome.kind !== 'ok') return

    await load()
    setOpen(null)
    setCuerpo(null)
    setNotice({
      type: 'success',
      title: 'Logs Deleted!',
      text: 'All log files were deleted successfully.',
    })
  }

  async function removeAllStats() {
    setConfirm(null)
    setBusy(true)
    const outcome = await deleteAllStats(token)
    setBusy(false)
    if (outcome.kind !== 'ok') return

    setNotice({
      type: 'success',
      title: 'Stats Deleted!',
      text: 'All stats files were deleted successfully.',
    })
  }

  if (files == null) return <Loading />

  const TEXTO_CONFIRM: Record<Confirmation, { title: string; text: string; label: string }> = {
    log: {
      title: 'Delete Log',
      text: `Are you sure you want to permanently delete the log file '${open ?? ''}'?`,
      label: 'Delete',
    },
    allLogs: {
      title: 'Delete All Logs',
      text: 'Are you sure you want to permanently delete all log files?',
      label: 'Delete All Logs',
    },
    allStats: {
      title: 'Delete All Stats',
      text: 'Are you sure you want to permanently delete all stats files?',
      label: 'Delete All Stats',
    },
  }

  return (
    <div className={styles.wrap}>
      <SectionHeader
        section="Logs"
        title="View Logs"
        actions={<>{/* logs.js:121 — "delete all logs" only exists if there are files. */}
          {canDeleteLogs && files.length > 0 && (
            <Button variant="danger" disabled={busy} onClick={() => setConfirm('allLogs')}>
              Delete All Logs
            </Button>
          )}
          {/* logs.js:117 — "delete all stats" is always offered. */}
          {canDeleteStats && (
            <Button variant="danger" disabled={busy} onClick={() => setConfirm('allStats')}>
              Delete All Stats
            </Button>
          )}</>}
      />

      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.dos}>
        <Panel title="Log Files" className={styles.panel}>
          <Body className={styles.pbList}>
            {files.length === 0 ? (
              <Empty>
                {notice?.type === 'danger'
                  ? 'Unable to load the log files.'
                  : 'No Log File Was Found'}
              </Empty>
            ) : (
              <div className={styles.logfiles}>
                {files.map((f) => (
                  <button
                    key={f.fileName}
                    type="button"
                    className={styles.logfile}
                    aria-current={open === f.fileName}
                    onClick={() => void view(f.fileName)}
                  >
                    <span className={styles.name}>{f.fileName}</span>
                    <span className={styles.sz}>[{f.size}]</span>
                  </button>
                ))}
              </div>
            )}
          </Body>
        </Panel>

        {open != null && (
          <Panel
            className={styles.panel}
            title={<span className={styles.mono}>{open}</span>}
            actions={
              <div className={styles.acts}>
                <Button disabled={busy} onClick={() => void download()}>
                  Download
                </Button>
                {canDeleteLogs && (
                  <Button variant="danger" disabled={busy} onClick={() => setConfirm('log')}>
                    Delete
                  </Button>
                )}
              </div>
            }
          >
            <Body>
              {loadingBody ? (
                <Loading />
              ) : (
                <pre className={styles.out}>{body ?? ''}</pre>
              )}
            </Body>
          </Panel>
        )}
      </div>

      <Confirm
        open={confirm !== null}
        title={confirm ? TEXTO_CONFIRM[confirm].title : ''}
        text={confirm ? TEXTO_CONFIRM[confirm].text : ''}
        label={confirm ? TEXTO_CONFIRM[confirm].label : ''}
        busy={busy}
        onClose={() => setConfirm(null)}
        onConfirm={() => {
          if (confirm === 'log') void removeLogFile()
          else if (confirm === 'allLogs') void removeAllLogs()
          else if (confirm === 'allStats') void removeAllStats()
        }}
      />
    </div>
  )
}
