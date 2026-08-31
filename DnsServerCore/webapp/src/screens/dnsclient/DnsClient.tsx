import { useState } from 'react'
import { PROTOCOLOS, TIPOS, prepararServidor, resolve } from '../../api/dnsclient'
import { Alert, type AlertType } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { LabeledInput, LabeledSelect } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import styles from './DnsClient.module.css'
import { Cuerpo, Panel } from '../../ui/Panel'

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
  /*
  Las respuestas en crudo de cada salto de la resolución.

  Upstream las enseña en el segundo panel de su acordeón —«Raw Responses (N)»,
  plegado y oculto si no hay ninguna (`dnsclient.js:178-194`)— y aquí faltaba
  entero: el tipo de la API ya declaraba `rawResponses`, pero no lo pintaba
  nadie. Es lo que deja ver qué contestó cada servidor por el camino cuando una
  consulta recursiva sale mal, que es justo cuando se abre esta pantalla.
  */
  const [crudas, setCrudas] = useState<unknown[]>([])
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
      setCrudas([])
      setAlert({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
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

      {alert && (
        <div className={styles.aviso}>
          <Alert type={alert.type} title={alert.title} onDismiss={() => setAlert(null)}>
            {alert.text}
          </Alert>
        </div>
      )}

      {/*
      La barra de consulta usaba etiquetas hechas a mano con `style` en línea
      —`fontSize: 11`, `gap: 5`, `marginBottom: 1`— en vez de los campos del
      sistema. Eran seis valores fuera de la escala en una sola pantalla, y por
      eso los rótulos de «Type» y «DNS-over-» no casaban con los de al lado.
      */}
      <div className={styles.filt}>
        <div className={styles.ancho}>
          <LabeledInput label="Server" mono value={server} onChange={(e) => setServer(e.target.value)} />
        </div>
        <div className={styles.medio}>
          <LabeledInput label="Domain" mono value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
        <div className={styles.corto}>
          <LabeledSelect label="Type" value={type} onChange={(e) => setType(e.target.value)}>
            {TIPOS.map((t) => <option key={t}>{t}</option>)}
          </LabeledSelect>
        </div>
        <div className={styles.corto}>
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
          acciones={<span className={styles.meta}>{protocol} · {type}</span>}
          className={styles.panel}
        >
          <Cuerpo>
            <pre className={styles.out}>{salida}</pre>

            {crudas.length > 0 && (
              <details className={styles.crudas}>
                <summary>Raw Responses ({crudas.length})</summary>
                {crudas.map((c, i) => (
                  <pre key={i} className={styles.out}>
                    {JSON.stringify(c, null, 2)}
                  </pre>
                ))}
              </details>
            )}
          </Cuerpo>
        </Panel>
      )}
    </>
  )
}
