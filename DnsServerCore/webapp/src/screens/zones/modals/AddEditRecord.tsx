import { useEffect, useRef, useState } from 'react'
import { listApps } from '../../../api/apps'
import {
  addRecord,
  updateRecord,
  zoneHasSvcbAutoHint,
  type ResourceRecord,
  type ZoneDetails,
} from '../../../api/records'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import {
  PROTOCOLOS_FORWARDER,
  PROXY_TYPES,
  ejemploDeForwarder,
  proxyEditable,
} from './add-zone'
import {
  RECORD_TYPES,
  buildRecordBody,
  formFromRecord,
  emptyForm,
  type RecordForm,
  type RecordMode,
} from '../record-form'
import { typesHiddenWhenAdding } from '../zone-view'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { GroupRow } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalAddEditRecord` (zone.js:4395 add, 5295 edit). A single form for all 23
types: changing the "Type" dropdown replaces the fields below.

All the logic about what travels and in what order it validates lives in
`registro-form.ts`. Only the fields are here.

**On edit the type cannot be changed**: upstream leaves the dropdown fixed
because the server identifies the record by its content and changing the type
would be deleting one and creating another.
*/

const DS_ALGORITHMS = [
  'RSAMD5 (1)', 'RSASHA1 (5)', 'RSASHA256 (8)', 'RSASHA512 (10)',
  'ECDSAP256SHA256 (13)', 'ECDSAP384SHA384 (14)', 'ED25519 (15)', 'ED448 (16)',
]
const DIGESTS_DS = ['SHA1 (1)', 'SHA256 (2)', 'SHA384 (4)']
const SSHFP_ALGORITHMS = ['RSA', 'DSA', 'ECDSA', 'Ed25519', 'Ed448']
const HUELLAS_SSHFP = ['SHA1', 'SHA256']
const USOS_TLSA = ['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE']
const SELECTORES_TLSA = ['Cert', 'SPKI']
const COINCIDENCIAS_TLSA = ['Full', 'SHA2-256', 'SHA2-512']

export interface AddEditRecordProps {
  open: boolean
  mode: RecordMode
  zone: string
  zoneInfo: ZoneDetails | null
  /** Every record in the zone: they are needed for the SVCB hints. */
  records: ResourceRecord[]
  /** Only on edit. */
  original?: ResourceRecord | null
  token: string | null
  node?: string
  onClose: () => void
  onDone: (a: Notice) => void
  /** The expiry TTL is reported because the row's "Disable" button uses it. */
  onExpiryTtl: (v: string) => void
}

export function AddEditRecord(p: AddEditRecordProps) {
  const [f, setF] = useState<RecordForm>(emptyForm)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const [apps, setApps] = useState<string[]>([])
  const [clases, setClases] = useState<string[]>([])
  const nombreRef = useRef<HTMLInputElement>(null)

  const editing = p.mode === 'update'
  const ocultos = p.zoneInfo ? typesHiddenWhenAdding(p.zoneInfo.type, p.zoneInfo.dnssecStatus) : []

  useEffect(() => {
    if (!p.open) return

    if (editing && p.original) {
      setF(formFromRecord(p.original, p.zone))
    } else {
      const initial = emptyForm()
      // The first visible type, not a blind "A": on a signed Primary the
      // dropdown starts the same, but on a Forwarder the hidden ones change.
      const first = RECORD_TYPES.find((t) => t !== 'SOA' && !ocultos.includes(t))
      initial.type = first ?? 'A'
      setF(initial)
    }
    setNotice(null)
    nombreRef.current?.focus()
    // `ocultos` is recalculated on every render; depending on it would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.open, p.mode, p.original, p.zone])

  // `loadAddRecordModalAppNames`: only the apps that handle APP records.
  useEffect(() => {
    if (!p.open || f.type !== 'APP') return
    void listApps(p.token, p.node ?? '').then((outcome) => {
      if (outcome.kind !== 'ok') return
      // Only the apps that bring an APP record handler (zone.js:4451).
      const withHandler = (outcome.data.response.apps ?? []).filter((a) =>
        (a.dnsApps ?? []).some((d) => d.isAppRecordRequestHandler),
      )
      setApps(withHandler.map((a) => a.name))
      const chosen = withHandler.find((a) => a.name === f.appName)
      setClases(
        (chosen?.dnsApps ?? [])
          .filter((d) => d.isAppRecordRequestHandler)
          .map((d) => d.classPath),
      )
    })
  }, [p.open, f.type, f.appName, p.token, p.node])

  const set = <K extends keyof RecordForm>(k: K, value: RecordForm[K]) =>
    setF((prev) => ({ ...prev, [k]: value }))

  async function save() {
    const hints = zoneHasSvcbAutoHint(p.records, f.type === 'A', f.type === 'AAAA')
    const r = buildRecordBody(f, {
      zone: p.zone,
      mode: p.mode,
      original: p.original ?? undefined,
      updateSvcbHints: hints,
    })

    if ('error' in r) {
      setNotice({ type: 'warning', title: r.error.title, text: r.error.text })
      if (r.error.field === 'name') nombreRef.current?.focus()
      return
    }

    setBusy(true)
    const outcome = editing
      ? await updateRecord(p.token, r.body, p.node ?? '')
      : await addRecord(p.token, r.body, p.node ?? '')
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    p.onExpiryTtl(f.expiryTtl)
    p.onClose()
    p.onDone(
      editing
        ? { type: 'success', title: 'Record Updated!', text: 'Resource record was updated successfully.' }
        : { type: 'success', title: 'Record Added!', text: 'Resource record was added successfully.' },
    )
  }

  return (
    <Dialog
      open={p.open}
      onOpenChange={(o) => !o && p.onClose()}
      size="medium"
      title={editing ? 'Edit Record' : 'Add Record'}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.fields}>
        <Field label="Name">
          {(id) => (
            <div className={styles.inline}>
              <Input
                id={id}
                mono
                ref={nombreRef}
                placeholder="@"
                value={f.name}
                onChange={(e) => set('name', e.target.value)}
              />
              <span className={styles.suffix}>.{p.zone}</span>
            </div>
          )}
        </Field>

        <Field label="Type">
          {(id) => (
            <Select
              id={id}
              className={styles.medio}
              disabled={editing}
              value={f.type}
              onChange={(e) => set('type', e.target.value)}
            >
              {RECORD_TYPES.filter(
                // SOA only appears on edit; the rest according to the zone type.
                (t) => (t === 'SOA' ? editing : !ocultos.includes(t)),
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
            <div className={styles.inline}>
              <Input
                id={id}
                mono
                className={styles.short}
                placeholder="3600"
                value={f.ttl}
                onChange={(e) => set('ttl', e.target.value)}
              />
              <span className={styles.suffix}>seconds (default 3600)</span>
            </div>
          )}
        </Field>

        <TypeFields f={f} set={set} apps={apps} clases={clases} editing={editing} />

        {/* "Overwrite" only exists when adding. */}
        {!editing && (
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
            <div className={styles.inline}>
              <Input
                id={id}
                mono
                className={styles.short}
                placeholder="0"
                value={f.expiryTtl}
                onChange={(e) => set('expiryTtl', e.target.value)}
              />
              <span className={styles.suffix}>seconds (set 0 to disable)</span>
            </div>
          )}
        </Field>
        <div className={styles.help}>
          Set to automatically delete the record when the value in seconds elapses since the record’s last
          modified time.
        </div>
      </div>
    </Dialog>
  )
}

interface FieldsProps {
  f: RecordForm
  set: <K extends keyof RecordForm>(k: K, value: RecordForm[K]) => void
  apps: string[]
  clases: string[]
  editing: boolean
}

function TypeFields({ f, set, apps, clases, editing }: FieldsProps) {
  const text = (
    label: string,
    key: keyof RecordForm,
    options: { mono?: boolean; short?: boolean; placeholder?: string } = {},
  ) => (
    <Field label={label}>
      {(id) => (
        <Input
          id={id}
          mono={options.mono}
          className={options.short ? styles.short : undefined}
          placeholder={options.placeholder}
          value={String(f[key] ?? '')}
          onChange={(e) => set(key, e.target.value as never)}
        />
      )}
    </Field>
  )

  const dropdown = (label: string, key: keyof RecordForm, valores: string[]) => (
    <Field label={label}>
      {(id) => (
        <Select id={id} value={String(f[key] ?? '')} onChange={(e) => set(key, e.target.value as never)}>
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
          {text(f.type === 'A' ? 'IPv4 Address' : 'IPv6 Address', 'value', { mono: true })}
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
          {text('Name Server', 'nsNameServer', { mono: true })}
          <Field label="Glue Addresses">
            {(id) => (
              <Textarea
                placeholder={`192.168.1.1
2001:db8::`}
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
          {text('Primary Name Server', 'soaPrimaryNameServer', { mono: true })}
          {text('Responsible Person', 'soaResponsiblePerson', { mono: true, placeholder: 'email address' })}
          {text('Serial', 'soaSerial', { mono: true, short: true })}
          {text('Refresh', 'soaRefresh', { mono: true, short: true })}
          {text('Retry', 'soaRetry', { mono: true, short: true })}
          {text('Expire', 'soaExpire', { mono: true, short: true })}
          {text('Minimum', 'soaMinimum', { mono: true, short: true })}
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
      return text('Canonical Name', 'value', { mono: true })

    case 'PTR':
      return text('Domain Name', 'value', { mono: true })

    case 'DNAME':
      return text('Delegation Name', 'value', { mono: true })

    case 'ANAME':
      return text('ANAME', 'value', { mono: true })

    case 'MX':
      return (
        <>
          {text('Preference', 'mxPreference', { mono: true, short: true, placeholder: '1' })}
          {text('Exchange', 'mxExchange', { mono: true })}
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
          {text('Mailbox', 'rpMailbox', { mono: true, placeholder: 'email address' })}
          {text('TXT Domain', 'rpTxtDomain', { mono: true, placeholder: '.' })}
        </>
      )

    case 'SRV':
      return (
        <>
          {text('Priority', 'srvPriority', { mono: true, short: true })}
          {text('Weight', 'srvWeight', { mono: true, short: true })}
          {text('Port', 'srvPort', { mono: true, short: true })}
          {text('Target', 'srvTarget', { mono: true })}
        </>
      )

    case 'NAPTR':
      return (
        <>
          {text('Order', 'naptrOrder', { mono: true, short: true })}
          {text('Preference', 'naptrPreference', { mono: true, short: true })}
          {text('Flags', 'naptrFlags', { mono: true, short: true })}
          {text('Services', 'naptrServices', { mono: true })}
          {text('Regular Expression', 'naptrRegexp', { mono: true })}
          {text('Replacement', 'naptrReplacement', { mono: true })}
        </>
      )

    case 'DS':
      return (
        <>
          {text('Key Tag', 'dsKeyTag', { mono: true, short: true, placeholder: 'key tag' })}
          {dropdown('DNSSEC Algorithm', 'dsAlgorithm', DS_ALGORITHMS)}
          {dropdown('Digest Type', 'dsDigestType', DIGESTS_DS)}
          {text('Digest', 'dsDigest', { mono: true, placeholder: 'hash string' })}
        </>
      )

    case 'SSHFP':
      return (
        <>
          {dropdown('Algorithm', 'sshfpAlgorithm', SSHFP_ALGORITHMS)}
          {dropdown('Fingerprint Type', 'sshfpFingerprintType', HUELLAS_SSHFP)}
          {text('Fingerprint', 'sshfpFingerprint', { mono: true, placeholder: 'hash string' })}
        </>
      )

    case 'TLSA':
      return (
        <>
          {dropdown('Certificate Usage', 'tlsaCertificateUsage', USOS_TLSA)}
          {dropdown('Selector', 'tlsaSelector', SELECTORES_TLSA)}
          {dropdown('Matching Type', 'tlsaMatchingType', COINCIDENCIAS_TLSA)}
          <Field label="Certificate Association Data">
            {(id) => (
              <Textarea
                placeholder={`5F95253A20A0957648DEBAAEB032F7C5720CD4F0DCF928840C55650687921DAE
          OR
-----BEGIN CERTIFICATE-----
MII...
-----END CERTIFICATE-----
`}
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
          {text('Priority', 'svcbPriority', { mono: true, short: true })}
          {text('Target Name', 'svcbTargetName', { mono: true })}
          <div className={styles.group}>
            <div className={styles.groupTitle}>Params</div>
            {f.svcbParams.map((par, i) => (
              <div key={i} className={styles.inline}>
                <Input
                  mono
                  aria-label={`Param key ${i + 1}`}
                  value={par.key}
                  onChange={(e) =>
                    set(
                      'svcbParams',
                      f.svcbParams.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)),
                    )
                  }
                />
                <Input
                  mono
                  aria-label={`Param value ${i + 1}`}
                  value={par.value}
                  onChange={(e) =>
                    set(
                      'svcbParams',
                      f.svcbParams.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)),
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
              <Button onClick={() => set('svcbParams', [...f.svcbParams, { key: '', value: '' }])}>
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
          {text('Priority', 'uriPriority', { mono: true, short: true })}
          {text('Weight', 'uriWeight', { mono: true, short: true })}
          {text('URI', 'uri', { mono: true })}
        </>
      )

    case 'CAA':
      return (
        <>
          {text('Flags', 'caaFlags', { mono: true, short: true, placeholder: '0' })}
          {text('Tag', 'caaTag', { mono: true, short: true, placeholder: 'issue' })}
          {text('Authority', 'caaValue', { mono: true })}
        </>
      )

    case 'FWD':
      return (
        <>
          <GroupRow modal label="Protocol">
            {PROTOCOLOS_FORWARDER.map((x) => (
              <label key={x.value} className={styles.chk}>
                <input
                  type="radio"
                  name="recordForwarderProtocol"
                  checked={f.forwarderProtocol === x.value}
                  onChange={() => set('forwarderProtocol', x.value)}
                />
                {x.label}
              </label>
            ))}
          </GroupRow>
          {text('Forwarder', 'forwarder', {
            mono: true,
            placeholder: ejemploDeForwarder(f.forwarderProtocol),
          })}
          {text('Forwarder Priority', 'forwarderPriority', { mono: true, short: true, placeholder: '0' })}
          <div className={styles.help}>
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
            {PROXY_TYPES.map((x) => (
              <label key={x.value} className={styles.chk}>
                <input
                  type="radio"
                  name="recordProxyType"
                  checked={f.proxyType === x.value}
                  onChange={() => set('proxyType', x.value)}
                />
                {x.label}
              </label>
            ))}
            <Field label="Proxy Server Address">
              {(id) => (
                <Input
                  placeholder="domain name or IP address"
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
                  placeholder="port"
                  id={id}
                  mono
                  className={styles.short}
                  disabled={!proxyEditable(f.proxyType)}
                  value={f.proxyPort}
                  onChange={(e) => set('proxyPort', e.target.value)}
                />
              )}
            </Field>
            <Field label="Proxy Server Username">
              {(id) => (
                <Input
                  placeholder="username"
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
                  placeholder="password"
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
          {/* On edit, the app and its class are read-only: only the data changes. */}
          <Field label="App Name">
            {(id) => (
              <Select
                id={id}
                disabled={editing}
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
                disabled={editing}
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
          {text('RR Type', 'unknownType', { mono: true, short: true, placeholder: 'type' })}
          {text('Value', 'value', { mono: true })}
        </>
      )
  }
}
