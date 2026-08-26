import { useState } from 'react'
import { PROTOCOLOS, TIPOS, prepararServidor, resolve } from '../../api/dnsclient'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { LabeledInput } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import styles from './DnsClient.module.css'

/*
Réplica de `resolveQuery()` (dnsclient.js:95-210). Los dos botones llaman al
mismo endpoint: «Import» sólo añade `import=true`.

Los textos de aviso son literales de upstream.
*/
interface AlertState { type: AlertType; title: string; text: string }

export function DnsClient({ token }: { token: string | null }) {
  const [server, setServer] = useState('This Server {this-server}')
  const [domain, setDomain] = useState('')
  const [type, setType] = useState('A')
  const [protocol, setProtocol] = useState('UDP')
  const [ecs, setEcs] = useState('')
  const [dnssec, setDnssec] = useState(true)
  const [salida, setSalida] = useState<string | null>(null)
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [busy, setBusy] = useState(false)

  async function lanzar(importar: boolean) {
    // El orden es el de upstream: extraer primero, comprobar después.
    const preparado = prepararServidor(server, protocol)

    if (preparado.server === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter a valid Name Server.' })
      return
    }
    if (domain.trim() === '') {
      setAlert({ type: 'warning', title: 'Missing!', text: 'Please enter a domain name to query.' })
      return
    }

    setBusy(true)
    setAlert(null)
    const outcome = await resolve(token, {
      server: preparado.server,
      domain,
      type,
      protocol: preparado.protocol,
      dnssec,
      eDnsClientSubnet: ecs,
      importar,
    })
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setSalida(null)
      setAlert({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
      return
    }

    const r = outcome.data.response
    setSalida(JSON.stringify(r.result, null, 2))

    if (r.warningMessage) {
      setAlert({ type: 'warning', title: 'Warning!', text: r.warningMessage })
    } else if (importar) {
      setAlert({
        type: 'success',
        title: 'Records Imported!',
        text: 'Resource records resolved by this DNS client query were successfully imported into this server.',
      })
    }
  }

  return (
    <>
      <SectionHeader titulo="DNS Client" />

      {alert && (
        <div style={{ marginBottom: 14 }}>
          <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
            {alert.text}
          </Alert>
        </div>
      )}

      <div className={styles.filt}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <LabeledInput label="Server" mono value={server} onChange={(e) => setServer(e.target.value)} />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <LabeledInput label="Domain" mono value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 5, width: 120 }}>
          <span style={{ fontSize: 11, color: 'var(--mute)', fontWeight: 650 }}>Type</span>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {TIPOS.map((t) => <option key={t}>{t}</option>)}
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 5, width: 120 }}>
          <span style={{ fontSize: 11, color: 'var(--mute)', fontWeight: 650 }}>DNS-over-</span>
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {PROTOCOLOS.map((t) => <option key={t}>{t}</option>)}
          </select>
        </label>
        <div style={{ width: 165 }}>
          <LabeledInput label="EDNS Client Subnet" mono value={ecs} onChange={(e) => setEcs(e.target.value)} />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, marginBottom: 7 }}>
          <input
            type="checkbox"
            checked={dnssec}
            onChange={(e) => setDnssec(e.target.checked)}
            style={{ width: 15, height: 15, accentColor: 'var(--acc)', padding: 0 }}
          />
          Enable DNSSEC Validation
        </label>
        <Button variant="primary" disabled={busy} onClick={() => void lanzar(false)} style={{ marginBottom: 1 }}>
          Resolve
        </Button>
        <Button disabled={busy} onClick={() => void lanzar(true)} style={{ marginBottom: 1 }}>
          Import
        </Button>
      </div>

      {salida === null ? (
        <div className={styles.vacio}>Run a query to see the response.</div>
      ) : (
        <div className={styles.panel}>
          <div className={styles.ph}>
            <h2>Response</h2>
            <span className={styles.meta}>{protocol} · {type}</span>
          </div>
          <div className={styles.pb}>
            <pre className={styles.out}>{salida}</pre>
          </div>
        </div>
      )}
    </>
  )
}
