import { useEffect, useRef, useState } from 'react'
import { listApps } from '../../../api/apps'
import {
  addRecord,
  updateRecord,
  zonaTienePistaSvcbAuto,
  type Registro,
  type ZonaDeRegistros,
} from '../../../api/registros'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import {
  PROTOCOLOS_FORWARDER,
  TIPOS_PROXY,
  ejemploDeForwarder,
  proxyEditable,
} from './anadir-zona'
import {
  TIPOS_REGISTRO,
  construirCuerpoRegistro,
  formularioDesdeRegistro,
  formularioVacio,
  type FormularioRegistro,
  type ModoRegistro,
} from '../registro-form'
import { tiposOcultosAlAnadir } from '../vista-zona'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'
import { GroupRow } from '../../../ui/Form'
import { avisoDeFallo } from '../../../lib/aviso'
import { Avisador } from '../../../ui/Avisador'

/*
`modalAddEditRecord` (zone.js:4395 alta, 5295 edición). Un solo formulario para
los 23 tipos: cambiar el desplegable «Type» sustituye los campos de abajo.

Toda la lógica de qué viaja y en qué orden se valida vive en
`registro-form.ts`. Aquí sólo están los campos.

**Editando, el tipo no se puede cambiar**: upstream deja el desplegable fijo
porque el servidor identifica el registro por su contenido y cambiar el tipo
sería borrar uno y crear otro.
*/

const ALGORITMOS_DS = [
  'RSAMD5 (1)', 'RSASHA1 (5)', 'RSASHA256 (8)', 'RSASHA512 (10)',
  'ECDSAP256SHA256 (13)', 'ECDSAP384SHA384 (14)', 'ED25519 (15)', 'ED448 (16)',
]
const DIGESTS_DS = ['SHA1 (1)', 'SHA256 (2)', 'SHA384 (4)']
const ALGORITMOS_SSHFP = ['RSA', 'DSA', 'ECDSA', 'Ed25519', 'Ed448']
const HUELLAS_SSHFP = ['SHA1', 'SHA256']
const USOS_TLSA = ['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE']
const SELECTORES_TLSA = ['Cert', 'SPKI']
const COINCIDENCIAS_TLSA = ['Full', 'SHA2-256', 'SHA2-512']

export interface AnadirEditarRegistroProps {
  abierto: boolean
  modo: ModoRegistro
  zone: string
  zona: ZonaDeRegistros | null
  /** Todos los registros de la zona: hacen falta para las pistas SVCB. */
  registros: Registro[]
  /** Sólo en edición. */
  original?: Registro | null
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Aviso) => void
  /** Se avisa del TTL de expiración porque el botón «Disable» de la fila lo usa. */
  onExpiryTtl: (v: string) => void
}

export function AnadirEditarRegistro(p: AnadirEditarRegistroProps) {
  const [f, setF] = useState<FormularioRegistro>(formularioVacio)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const [apps, setApps] = useState<string[]>([])
  const [clases, setClases] = useState<string[]>([])
  const nombreRef = useRef<HTMLInputElement>(null)

  const edicion = p.modo === 'update'
  const ocultos = p.zona ? tiposOcultosAlAnadir(p.zona.type, p.zona.dnssecStatus) : []

  useEffect(() => {
    if (!p.abierto) return

    if (edicion && p.original) {
      setF(formularioDesdeRegistro(p.original, p.zone))
    } else {
      const inicial = formularioVacio()
      // El primer tipo visible, no «A» a ciegas: en una Primary firmada el
      // desplegable empieza igual, pero en una Forwarder los ocultos cambian.
      const primero = TIPOS_REGISTRO.find((t) => t !== 'SOA' && !ocultos.includes(t))
      inicial.type = primero ?? 'A'
      setF(inicial)
    }
    setAviso(null)
    nombreRef.current?.focus()
    // `ocultos` se recalcula en cada render; depender de él dispararía un bucle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.abierto, p.modo, p.original, p.zone])

  // `loadAddRecordModalAppNames`: sólo los apps que manejan registros APP.
  useEffect(() => {
    if (!p.abierto || f.type !== 'APP') return
    void listApps(p.token, p.node ?? '').then((outcome) => {
      if (outcome.kind !== 'ok') return
      // Sólo los apps que traen un manejador de registros APP (zone.js:4451).
      const conManejador = (outcome.data.response.apps ?? []).filter((a) =>
        (a.dnsApps ?? []).some((d) => d.isAppRecordRequestHandler),
      )
      setApps(conManejador.map((a) => a.name))
      const elegido = conManejador.find((a) => a.name === f.appName)
      setClases(
        (elegido?.dnsApps ?? [])
          .filter((d) => d.isAppRecordRequestHandler)
          .map((d) => d.classPath),
      )
    })
  }, [p.abierto, f.type, f.appName, p.token, p.node])

  const set = <K extends keyof FormularioRegistro>(k: K, valor: FormularioRegistro[K]) =>
    setF((prev) => ({ ...prev, [k]: valor }))

  async function guardar() {
    const pistas = zonaTienePistaSvcbAuto(p.registros, f.type === 'A', f.type === 'AAAA')
    const r = construirCuerpoRegistro(f, {
      zone: p.zone,
      modo: p.modo,
      original: p.original ?? undefined,
      updateSvcbHints: pistas,
    })

    if ('error' in r) {
      setAviso({ type: 'warning', title: r.error.title, text: r.error.text })
      if (r.error.campo === 'name') nombreRef.current?.focus()
      return
    }

    setOcupado(true)
    const outcome = edicion
      ? await updateRecord(p.token, r.body, p.node ?? '')
      : await addRecord(p.token, r.body, p.node ?? '')
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    p.onExpiryTtl(f.expiryTtl)
    p.onCerrar()
    p.onHecho(
      edicion
        ? { type: 'success', title: 'Record Updated!', text: 'Resource record was updated successfully.' }
        : { type: 'success', title: 'Record Added!', text: 'Resource record was added successfully.' },
    )
  }

  return (
    <Dialog
      open={p.abierto}
      onOpenChange={(o) => !o && p.onCerrar()}
      tamano="medio"
      title={edicion ? 'Edit Record' : 'Add Record'}
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      <div className={styles.campos}>
        <Field label="Name">
          {(id) => (
            <div className={styles.enLinea}>
              <Input
                id={id}
                mono
                ref={nombreRef}
                placeholder="@"
                value={f.name}
                onChange={(e) => set('name', e.target.value)}
              />
              <span className={styles.sufijo}>.{p.zone}</span>
            </div>
          )}
        </Field>

        <Field label="Type">
          {(id) => (
            <Select
              id={id}
              className={styles.medio}
              disabled={edicion}
              value={f.type}
              onChange={(e) => set('type', e.target.value)}
            >
              {TIPOS_REGISTRO.filter(
                // SOA sólo aparece editando; el resto según el tipo de zona.
                (t) => (t === 'SOA' ? edicion : !ocultos.includes(t)),
              ).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>

        <Field label="TTL">
          {(id) => (
            <div className={styles.enLinea}>
              <Input
                id={id}
                mono
                className={styles.corto}
                placeholder="3600"
                value={f.ttl}
                onChange={(e) => set('ttl', e.target.value)}
              />
              <span className={styles.sufijo}>seconds (default 3600)</span>
            </div>
          )}
        </Field>

        <CamposDelTipo f={f} set={set} apps={apps} clases={clases} edicion={edicion} />

        {/* «Overwrite» sólo existe dando de alta. */}
        {!edicion && (
          <label className={styles.chk}>
            <input type="checkbox" checked={f.overwrite} onChange={(e) => set('overwrite', e.target.checked)} />
            Overwrite existing records
          </label>
        )}

        <Field label="Comments">
          {(id) => (
            <Textarea
              id={id}
              rows={2}
              value={f.comments}
              onChange={(e) => set('comments', e.target.value)}
            />
          )}
        </Field>

        <Field label="Expiry TTL">
          {(id) => (
            <div className={styles.enLinea}>
              <Input
                id={id}
                mono
                className={styles.corto}
                placeholder="0"
                value={f.expiryTtl}
                onChange={(e) => set('expiryTtl', e.target.value)}
              />
              <span className={styles.sufijo}>seconds (set 0 to disable)</span>
            </div>
          )}
        </Field>
        <div className={styles.ayuda}>
          Set to automatically delete the record when the value in seconds elapses since the record’s last
          modified time.
        </div>
      </div>
    </Dialog>
  )
}

interface CamposProps {
  f: FormularioRegistro
  set: <K extends keyof FormularioRegistro>(k: K, valor: FormularioRegistro[K]) => void
  apps: string[]
  clases: string[]
  edicion: boolean
}

function CamposDelTipo({ f, set, apps, clases, edicion }: CamposProps) {
  const texto = (
    etiqueta: string,
    clave: keyof FormularioRegistro,
    opciones: { mono?: boolean; corto?: boolean; placeholder?: string } = {},
  ) => (
    <Field label={etiqueta}>
      {(id) => (
        <Input
          id={id}
          mono={opciones.mono}
          className={opciones.corto ? styles.corto : undefined}
          placeholder={opciones.placeholder}
          value={String(f[clave] ?? '')}
          onChange={(e) => set(clave, e.target.value as never)}
        />
      )}
    </Field>
  )

  const desplegable = (etiqueta: string, clave: keyof FormularioRegistro, valores: string[]) => (
    <Field label={etiqueta}>
      {(id) => (
        <Select id={id} value={String(f[clave] ?? '')} onChange={(e) => set(clave, e.target.value as never)}>
          <option value="" />
          {valores.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </Select>
      )}
    </Field>
  )

  switch (f.type.toUpperCase()) {
    case 'A':
    case 'AAAA':
      return (
        <>
          {texto(f.type === 'A' ? 'IPv4 Address' : 'IPv6 Address', 'valor', { mono: true })}
          <label className={styles.chk}>
            <input type="checkbox" checked={f.ptr} onChange={(e) => set('ptr', e.target.checked)} />
            Add reverse (PTR) record
          </label>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.createPtrZone}
              onChange={(e) => set('createPtrZone', e.target.checked)}
            />
            Create reverse zone if it does not exists
          </label>
        </>
      )

    case 'NS':
      return (
        <>
          {texto('Name Server', 'nsNameServer', { mono: true })}
          <Field label="Glue Addresses">
            {(id) => (
              <Textarea
                id={id}
                mono
                className={styles.area}
                value={f.nsGlue}
                onChange={(e) => set('nsGlue', e.target.value)}
              />
            )}
          </Field>
        </>
      )

    case 'SOA':
      return (
        <>
          {texto('Primary Name Server', 'soaPrimaryNameServer', { mono: true })}
          {texto('Responsible Person', 'soaResponsiblePerson', { mono: true })}
          {texto('Serial', 'soaSerial', { mono: true, corto: true })}
          {texto('Refresh', 'soaRefresh', { mono: true, corto: true })}
          {texto('Retry', 'soaRetry', { mono: true, corto: true })}
          {texto('Expire', 'soaExpire', { mono: true, corto: true })}
          {texto('Minimum', 'soaMinimum', { mono: true, corto: true })}
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.soaUseSerialDateScheme}
              onChange={(e) => set('soaUseSerialDateScheme', e.target.checked)}
            />
            Use Serial Date Scheme
          </label>
        </>
      )

    case 'CNAME':
      return texto('Canonical Name', 'valor', { mono: true })

    case 'PTR':
      return texto('Domain Name', 'valor', { mono: true })

    case 'DNAME':
      return texto('Delegation Name', 'valor', { mono: true })

    case 'ANAME':
      return texto('ANAME', 'valor', { mono: true })

    case 'MX':
      return (
        <>
          {texto('Preference', 'mxPreference', { mono: true, corto: true, placeholder: '1' })}
          {texto('Exchange', 'mxExchange', { mono: true })}
        </>
      )

    case 'TXT':
      return (
        <>
          <Field label="Text Data">
            {(id) => (
              <Textarea
                id={id}
                mono
                className={styles.area}
                value={f.txt}
                onChange={(e) => set('txt', e.target.value)}
              />
            )}
          </Field>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.txtSplitText}
              onChange={(e) => set('txtSplitText', e.target.checked)}
            />
            Split text into multiple character strings
          </label>
        </>
      )

    case 'RP':
      return (
        <>
          {texto('Mailbox', 'rpMailbox', { mono: true })}
          {texto('TXT Domain', 'rpTxtDomain', { mono: true })}
        </>
      )

    case 'SRV':
      return (
        <>
          {texto('Priority', 'srvPriority', { mono: true, corto: true })}
          {texto('Weight', 'srvWeight', { mono: true, corto: true })}
          {texto('Port', 'srvPort', { mono: true, corto: true })}
          {texto('Target', 'srvTarget', { mono: true })}
        </>
      )

    case 'NAPTR':
      return (
        <>
          {texto('Order', 'naptrOrder', { mono: true, corto: true })}
          {texto('Preference', 'naptrPreference', { mono: true, corto: true })}
          {texto('Flags', 'naptrFlags', { mono: true, corto: true })}
          {texto('Services', 'naptrServices', { mono: true })}
          {texto('Regular Expression', 'naptrRegexp', { mono: true })}
          {texto('Replacement', 'naptrReplacement', { mono: true })}
        </>
      )

    case 'DS':
      return (
        <>
          {texto('Key Tag', 'dsKeyTag', { mono: true, corto: true })}
          {desplegable('DNSSEC Algorithm', 'dsAlgorithm', ALGORITMOS_DS)}
          {desplegable('Digest Type', 'dsDigestType', DIGESTS_DS)}
          {texto('Digest', 'dsDigest', { mono: true })}
        </>
      )

    case 'SSHFP':
      return (
        <>
          {desplegable('Algorithm', 'sshfpAlgorithm', ALGORITMOS_SSHFP)}
          {desplegable('Fingerprint Type', 'sshfpFingerprintType', HUELLAS_SSHFP)}
          {texto('Fingerprint', 'sshfpFingerprint', { mono: true })}
        </>
      )

    case 'TLSA':
      return (
        <>
          {desplegable('Certificate Usage', 'tlsaCertificateUsage', USOS_TLSA)}
          {desplegable('Selector', 'tlsaSelector', SELECTORES_TLSA)}
          {desplegable('Matching Type', 'tlsaMatchingType', COINCIDENCIAS_TLSA)}
          <Field label="Certificate Association Data">
            {(id) => (
              <Textarea
                id={id}
                mono
                className={styles.area}
                value={f.tlsaCertificateAssociationData}
                onChange={(e) => set('tlsaCertificateAssociationData', e.target.value)}
              />
            )}
          </Field>
        </>
      )

    case 'SVCB':
    case 'HTTPS':
      return (
        <>
          {texto('Priority', 'svcbPriority', { mono: true, corto: true })}
          {texto('Target Name', 'svcbTargetName', { mono: true })}
          <div className={styles.grupo}>
            <div className={styles.grupoTit}>Params</div>
            {f.svcbParams.map((par, i) => (
              <div key={i} className={styles.enLinea}>
                <Input
                  mono
                  aria-label={`Param key ${i + 1}`}
                  value={par.clave}
                  onChange={(e) =>
                    set(
                      'svcbParams',
                      f.svcbParams.map((x, j) => (j === i ? { ...x, clave: e.target.value } : x)),
                    )
                  }
                />
                <Input
                  mono
                  aria-label={`Param value ${i + 1}`}
                  value={par.valor}
                  onChange={(e) =>
                    set(
                      'svcbParams',
                      f.svcbParams.map((x, j) => (j === i ? { ...x, valor: e.target.value } : x)),
                    )
                  }
                />
                <Button
                  size="sm"
                  onClick={() => set('svcbParams', f.svcbParams.filter((_, j) => j !== i))}
                >
                  Remove
                </Button>
              </div>
            ))}
            <div>
              <Button onClick={() => set('svcbParams', [...f.svcbParams, { clave: '', valor: '' }])}>
                Add Param
              </Button>
            </div>
          </div>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.svcbAutoIpv4Hint}
              onChange={(e) => set('svcbAutoIpv4Hint', e.target.checked)}
            />
            Use Automatic IPv4 Hint
          </label>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.svcbAutoIpv6Hint}
              onChange={(e) => set('svcbAutoIpv6Hint', e.target.checked)}
            />
            Use Automatic IPv6 Hint
          </label>
        </>
      )

    case 'URI':
      return (
        <>
          {texto('Priority', 'uriPriority', { mono: true, corto: true })}
          {texto('Weight', 'uriWeight', { mono: true, corto: true })}
          {texto('URI', 'uri', { mono: true })}
        </>
      )

    case 'CAA':
      return (
        <>
          {texto('Flags', 'caaFlags', { mono: true, corto: true, placeholder: '0' })}
          {texto('Tag', 'caaTag', { mono: true, corto: true, placeholder: 'issue' })}
          {texto('Authority', 'caaValue', { mono: true })}
        </>
      )

    case 'FWD':
      return (
        <>
          <GroupRow modal label="Protocol">
            {PROTOCOLOS_FORWARDER.map((x) => (
              <label key={x.valor} className={styles.chk}>
                <input
                  type="radio"
                  name="recordForwarderProtocol"
                  checked={f.forwarderProtocol === x.valor}
                  onChange={() => set('forwarderProtocol', x.valor)}
                />
                {x.etiqueta}
              </label>
            ))}
          </GroupRow>
          {texto('Forwarder', 'forwarder', {
            mono: true,
            placeholder: ejemploDeForwarder(f.forwarderProtocol),
          })}
          {texto('Forwarder Priority', 'forwarderPriority', { mono: true, corto: true })}
          <div className={styles.ayuda}>
            Forwarders are sorted by priority value i.e. forwarder with low priority value will be
            queried before trying for forwarder with high priority value. Forwarders with the same
            priority value will be queried concurrently.
          </div>
          <label className={styles.chk}>
            <input
              type="checkbox"
              checked={f.forwarderDnssecValidation}
              onChange={(e) => set('forwarderDnssecValidation', e.target.checked)}
            />
            Enable DNSSEC Validation
          </label>
          <GroupRow modal label="Network Proxy">
            {TIPOS_PROXY.map((x) => (
              <label key={x.valor} className={styles.chk}>
                <input
                  type="radio"
                  name="recordProxyType"
                  checked={f.proxyType === x.valor}
                  onChange={() => set('proxyType', x.valor)}
                />
                {x.etiqueta}
              </label>
            ))}
            <Field label="Proxy Server Address">
              {(id) => (
                <Input
                  id={id}
                  mono
                  disabled={!proxyEditable(f.proxyType)}
                  value={f.proxyAddress}
                  onChange={(e) => set('proxyAddress', e.target.value)}
                />
              )}
            </Field>
            <Field label="Proxy Server Port">
              {(id) => (
                <Input
                  id={id}
                  mono
                  className={styles.corto}
                  disabled={!proxyEditable(f.proxyType)}
                  value={f.proxyPort}
                  onChange={(e) => set('proxyPort', e.target.value)}
                />
              )}
            </Field>
            <Field label="Proxy Server Username">
              {(id) => (
                <Input
                  id={id}
                  disabled={!proxyEditable(f.proxyType)}
                  value={f.proxyUsername}
                  onChange={(e) => set('proxyUsername', e.target.value)}
                />
              )}
            </Field>
            <Field label="Proxy Server Password">
              {(id) => (
                <Input
                  id={id}
                  type="password"
                  disabled={!proxyEditable(f.proxyType)}
                  value={f.proxyPassword}
                  onChange={(e) => set('proxyPassword', e.target.value)}
                />
              )}
            </Field>
          </GroupRow>
        </>
      )

    case 'APP':
      return (
        <>
          {/* Editando, el app y su clase son de sólo lectura: sólo cambia el dato. */}
          <Field label="App Name">
            {(id) => (
              <Select
                id={id}
                disabled={edicion}
                value={f.appName}
                onChange={(e) => set('appName', e.target.value)}
              >
                <option value="" />
                {apps.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Class Path">
            {(id) => (
              <Select
                id={id}
                disabled={edicion}
                value={f.classPath}
                onChange={(e) => set('classPath', e.target.value)}
              >
                <option value="" />
                {clases.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Record Data (if any)">
            {(id) => (
              <Textarea
                id={id}
                mono
                className={styles.area}
                value={f.recordData}
                onChange={(e) => set('recordData', e.target.value)}
              />
            )}
          </Field>
        </>
      )

    default:
      return (
        <>
          {texto('RR Type', 'unknownType', { mono: true, corto: true })}
          {texto('Value', 'valor', { mono: true })}
        </>
      )
  }
}
