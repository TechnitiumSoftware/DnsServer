import { useState } from 'react'
import { PROTOCOLOS, TYPES, prepararServidor, resolve } from '../../api/dnsclient'
import { type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { LabeledInput, LabeledSelect } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { Details } from '../../ui/Detalles'
import styles from './DnsClient.module.css'
import { Body, Panel } from '../../ui/Panel'
import { noticeFromFailure } from '../../lib/aviso'
import { Notifier } from '../../ui/Avisador'

/*
A replica of `resolveQuery()` (dnsclient.js:95-210). Both buttons call the same
endpoint: "Import" only adds `import=true`.

The alert texts are upstream literals.
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
  /*
  The raw responses of each hop of the resolution.

  Upstream shows them in the second panel of its accordion —"Raw Responses (N)",
  collapsed and hidden if there are none (`dnsclient.js:178-194`)— and here it was
  missing entirely: the API type already declared `rawResponses`, but nobody drew
  it. It is what lets you see what each server answered along the way when a
  recursive query goes wrong, which is exactly when this screen gets opened.
  */
  const [crudas, setCrudas] = useState<unknown[]>([])
  const [alert, setAlert] = useState<AlertState | null>(null)
  const [busy, setBusy] = useState(false)

  async function lanzar(importar: boolean) {
    // The order is upstream's: extract first, check afterwards.
    const ready = prepararServidor(server, protocol)

    if (ready.server === '') {
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
      server: ready.server,
      domain,
      type,
      protocol: ready.protocol,
      dnssec,
      eDnsClientSubnet: ecs,
      importar,
    })
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setSalida(null)
      setCrudas([])
      setAlert(noticeFromFailure(outcome))
      return
    }

    const r = outcome.data.response
    setSalida(JSON.stringify(r.result, null, 2))
    setCrudas(r.rawResponses ?? [])

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

      <Notifier notice={alert} onCerrar={() => setAlert(null)} />

      {/*
      The query bar used labels made by hand with inline `style` —`fontSize: 11`,
      `gap: 5`, `marginBottom: 1`— instead of the system's fields. They were six
      values off the scale on a single screen, and that is why the "Type" and
      "DNS-over-" labels did not match the ones next to them.
      */}
      <div className={styles.filt}>
        <div className={styles.width}>
          <LabeledInput label="Server" mono value={server} onChange={(e) => setServer(e.target.value)} />
        </div>
        <div className={styles.medio}>
          <LabeledInput label="Domain" placeholder="example.com" mono value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
        <div className={styles.short}>
          <LabeledSelect label="Type" value={type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => <option key={t}>{t}</option>)}
          </LabeledSelect>
        </div>
        <div className={styles.short}>
          <LabeledSelect label="DNS-over-" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {PROTOCOLOS.map((t) => <option key={t}>{t}</option>)}
          </LabeledSelect>
        </div>
        <div className={styles.ecs}>
          <LabeledInput label="EDNS Client Subnet" mono value={ecs} onChange={(e) => setEcs(e.target.value)} />
        </div>
        <label className={styles.chk}>
          <input type="checkbox" checked={dnssec} onChange={(e) => setDnssec(e.target.checked)} />
          Enable DNSSEC Validation
        </label>
        <Button variant="primary" disabled={busy} onClick={() => void lanzar(false)}>
          Resolve
        </Button>
        <Button disabled={busy} onClick={() => void lanzar(true)}>
          Import
        </Button>
      </div>

      {salida === null ? (
        <Empty>Run a query to see the response.</Empty>
      ) : (
        <Panel
          titulo="Response"
          actions={<span className={styles.meta}>{protocol} · {type}</span>}
          className={styles.panel}
        >
          <Body>
            <pre className={styles.out}>{salida}</pre>

            {crudas.length > 0 && (
              <Details className={styles.crudas} summary={`Raw Responses (${crudas.length})`}>
                {crudas.map((c, i) => (
                  <pre key={i} className={styles.out}>
                    {JSON.stringify(c, null, 2)}
                  </pre>
                ))}
              </Details>
            )}
          </Body>
        </Panel>
      )}
    </>
  )
}
