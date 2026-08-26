import { useEffect, useState } from 'react'
import { checkForUpdate } from '../../api/user'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import styles from './About.module.css'

interface Info { version: string; uptimestamp: string; dnsServerDomain: string }

/** «hace 2 horas» a partir de una marca ISO, sin librería de fechas. */
export function desde(iso: string, ahora = Date.now()): string {
  const ms = ahora - new Date(iso).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const min = Math.floor(ms / 60000)
  if (min < 1) return 'hace unos segundos'
  if (min < 60) return `hace ${min} ${min === 1 ? 'minuto' : 'minutos'}`
  const h = Math.floor(min / 60)
  if (h < 24) return `hace ${h} ${h === 1 ? 'hora' : 'horas'}`
  const d = Math.floor(h / 24)
  return `hace ${d} ${d === 1 ? 'día' : 'días'}`
}

export function About({ token, info }: { token: string | null; info?: Info }) {
  const [update, setUpdate] = useState<'sin-mirar' | 'mirando' | 'al-dia' | 'hay'>('sin-mirar')

  useEffect(() => {
    void (async () => {
      const r = await checkForUpdate(token)
      if (r.kind === 'skipped') return
      if (r.kind === 'ok') {
        const d = r.data as { response?: { updateAvailable?: boolean } }
        setUpdate(d.response?.updateAvailable ? 'hay' : 'al-dia')
      }
    })()
  }, [token])

  async function mirar() {
    setUpdate('mirando')
    const r = await checkForUpdate(token, true)
    if (r.kind === 'ok') {
      const d = r.data as { response?: { updateAvailable?: boolean } }
      setUpdate(d.response?.updateAvailable ? 'hay' : 'al-dia')
    } else setUpdate('sin-mirar')
  }

  return (
    <>
      <SectionHeader titulo="About" />
    <div className={styles.grid}>
      <div className={styles.panel}>
        <div className={styles.pb}>
          <div className={styles.head}>
            <span className={styles.mark}>T</span>
            <div>
              <h2 className={styles.h1}>Technitium DNS Server</h2>
              <div className={styles.ver}>Version {info?.version ?? '—'}</div>
            </div>
          </div>
          <div className={styles.prose}>
            <p>Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)</p>
            <p>
              This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
              welcome to redistribute it under certain conditions.
            </p>
            <p>
              Source code available under GNU General Public License v3.0 on{' '}
              <a href="https://github.com/TechnitiumSoftware/DnsServer" target="_blank" rel="noreferrer">GitHub</a>.
            </p>
            <h4>What&apos;s New?</h4>
            <p>Read the change log to know what&apos;s new in this release.</p>
            <h4>API Documentation</h4>
            <p>
              The DNS Server HTTP API allows any 3rd party app or script to configure the DNS Server.
              The HTTP API is used by this web console and thus all the actions that this web console
              does can be performed via the API.
            </p>
          </div>
        </div>
      </div>

      <div className={styles.col}>
        <div className={styles.panel}>
          <div className={styles.ph}><h2>Server</h2></div>
          <div className={styles.pb}>
            <dl className={styles.kv}>
              <dt>Version</dt><dd>{info?.version ?? '—'}</dd>
              <dt>Domain</dt><dd>{info?.dnsServerDomain ?? '—'}</dd>
              <dt>Up since</dt><dd>{info ? new Date(info.uptimestamp).toLocaleString('es-ES') : '—'}</dd>
              <dt>Uptime</dt><dd>{info ? desde(info.uptimestamp) : '—'}</dd>
            </dl>
          </div>
        </div>
        <div className={styles.panel}>
          <div className={styles.ph}><h2>Update</h2></div>
          <div className={styles.pb}>
            {update === 'al-dia' && <Alert type="info" title="Note:">No update available. You are running the latest version.</Alert>}
            {update === 'hay' && <Alert type="success" title="New Update Available!">Se puede actualizar a una versión más reciente.</Alert>}
            {update === 'sin-mirar' && <Empty compacto>Update notifications are turned off for this server.</Empty>}
            <div style={{ marginTop: 10 }}>
              <Button disabled={update === 'mirando'} onClick={() => void mirar()}>Check for Update</Button>
            </div>
          </div>
        </div>
      </div>
    </div>
    </>
  )
}
