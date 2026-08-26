import { useEffect, useState } from 'react'
import { checkForUpdate } from '../../api/user'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { desdeAhora, fechaHora } from '../../lib/fechas'
import styles from './About.module.css'

interface Info { version: string; uptimestamp: string; dnsServerDomain: string }

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
              <dt>Up since</dt><dd>{info ? fechaHora(info.uptimestamp) : '—'}</dd>
              <dt>Uptime</dt><dd>{info ? desdeAhora(info.uptimestamp) : '—'}</dd>
            </dl>
          </div>
        </div>
        <div className={styles.panel}>
          <div className={styles.ph}><h2>Update</h2></div>
          <div className={styles.pb}>
            {update === 'al-dia' && <Alert type="info" title="Note:">No update available. You are running the latest version.</Alert>}
            {/*
            main.js:751-767 — el título por defecto es «New Update Available!» y
            el MENSAJE lo manda el servidor; si no viene, upstream no enseña
            ninguno. La frase que había aquí estaba inventada, y en castellano.
            */}
            {update === 'hay' && <Alert type="success" title="New Update Available!" />}
            {update === 'sin-mirar' && <Empty compacto>Update notifications are turned off for this server.</Empty>}
            <div className={styles.accion}>
              <Button disabled={update === 'mirando'} onClick={() => void mirar()}>Check for Update</Button>
            </div>
          </div>
        </div>
      </div>
    </div>
    </>
  )
}
