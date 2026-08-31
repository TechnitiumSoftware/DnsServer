import { useEffect, useRef, useState } from 'react'
import { createZone, listCatalogs } from '../../../api/zones'
import { getTsigKeyNames } from '../../../api/settings'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import {
  acceptsZoneFile,
  buildAddParams,
  ejemploDeForwarder,
  formularioAltaInicial,
  proxyEditable,
  PROTOCOLOS_FORWARDER,
  TRANSFER_PROTOCOLS,
  seccionesVisibles,
  ADD_TYPES,
  PROXY_TYPES,
  type FormularioAlta,
  type AddZoneKind,
} from './add-zone'
import { HelpText, Externo } from '../../../ui/Externo'
import { RFC_ZONEMD } from '../references'
import { GroupRow, Row } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalAddZone` (zone.js:2726 and 2911). Eight zone types, each with its own form.
The decision about what shows and what travels is in `anadir-zona.ts`, which
tests without mounting anything.

The catalog is only offered **if the server returned one**: upstream marks the
dropdown with `hasItems` and the `switch`'s branches check it before showing it.
A server with no catalog zones does not show that field at all.
*/

export function AddZone({
  open,
  token,
  node = '',
  useSoaSerialDateScheme,
  dnssecValidation,
  onClose,
  onCreated,
}: {
  open: boolean
  token: string | null
  node?: string
  /** Both inherit from Settings' global setting, not from `false`. */
  useSoaSerialDateScheme: boolean
  dnssecValidation: boolean
  onClose: () => void
  onCreated: (domain: string, notice: Notice) => void
}) {
  const [f, setF] = useState<FormularioAlta>(() =>
    formularioAltaInicial(useSoaSerialDateScheme, dnssecValidation),
  )
  const [catalogos, setCatalogos] = useState<string[]>([])
  const [tsigKeys, setTsigKeys] = useState<string[]>([])
  const [archivo, setArchivo] = useState<File | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const zoneRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setF(formularioAltaInicial(useSoaSerialDateScheme, dnssecValidation))
    setArchivo(null)
    setNotice(null)
    void listCatalogs(token, node).then((c) => setCatalogos(c ?? []))
    void getTsigKeyNames(token, node).then(setTsigKeys)
    zoneRef.current?.focus()
  }, [open, token, node, useSoaSerialDateScheme, dnssecValidation])

  const v = seccionesVisibles(f.type, f.initializeForwarder)
  const set = <K extends keyof FormularioAlta>(k: K, value: FormularioAlta[K]) =>
    setF((prev) => ({ ...prev, [k]: value }))

  function changeType(type: AddZoneKind) {
    const secciones = seccionesVisibles(type, f.initializeForwarder)
    setF((prev) => ({ ...prev, type, zone: secciones.fixedZone ?? prev.zone }))
  }

  async function create() {
    const r = buildAddParams(f)
    if ('error' in r) {
      setNotice({ type: 'warning', title: r.error.title, text: r.error.text })
      if (r.error.field === 'zone') zoneRef.current?.focus()
      return
    }

    setBusy(true)
    const outcome = await createZone(
      token,
      r.params,
      acceptsZoneFile(f.type) ? archivo : null,
      node,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    // Upstream opens the newly created zone, it does not go back to the list.
    onCreated(outcome.data.response.domain, {
      type: 'success',
      title: 'Zone Added!',
      text: 'Zone was added successfully.',
    })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="medium"
      title="Add Zone"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void create()}>
            Add
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.fields}>
        <Field label="Zone">
          {(id) => (
            <Input
              placeholder="example.com or 192.168.0.0/24 or 2001:db8::/64"
              id={id}
              mono
              ref={zoneRef}
              disabled={v.fixedZone != null}
              value={f.zone}
              onChange={(e) => set('zone', e.target.value)}
            />
          )}
        </Field>

        <GroupRow modal label="Zone Type">
          {ADD_TYPES.map((t) => (
            <label key={t.value} className={styles.chk}>
              <input
                type="radio"
                name="addZoneType"
                checked={f.type === t.value}
                onChange={() => changeType(t.value)}
              />
              {/*
              `.chk` is `display:flex`, so every child of the label is an item:
              without this `span` the link and the brackets split into three boxes
              —"Secondary ROOT Zone ( RFC 8806 )"— and the link stopped being
              inside a sentence, which is what grants it the target-size
              exception. Wrapped, it is text again.
              */}
              <span>
                {t.label}
                {t.reference && (
                  <>
                    {' ('}
                    <Externo href={t.reference.href}>{t.reference.text}</Externo>
                    {')'}
                  </>
                )}
              </span>
            </label>
          ))}
        </GroupRow>

        {v.catalogo && catalogos.length > 0 && (
          <Row modal label="Catalog Zone" help={<>Select a Catalog zone to register as its member zone.</>}>
            {(id) => (
              <Select id={id} value={f.catalog} onChange={(e) => set('catalog', e.target.value)}>
                <option value="" />
                {catalogos.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
            )}
          </Row>
        )}

        {v.casillaInicializarForwarder && (
          <GroupRow modal label="Conditional Forwarder">
            <label className={styles.chk}>
              <input
                type="checkbox"
                checked={f.initializeForwarder}
                onChange={(e) => set('initializeForwarder', e.target.checked)}
              />
              Initialize Forwarder (FWD) Record
            </label>
          </GroupRow>
        )}

        {v.zoneFile && (
          <Row modal label="Import Zone File (Optional)">
            {(id) => (
              <Input
                id={id}
                type="file"
                onChange={(e) => setArchivo(e.target.files?.[0] ?? null)}
              />
            )}
          </Row>
        )}

        {v.serieSoa && (
          <GroupRow modal label="Zone Serial">
            <label className={styles.chk}>
              <input
                type="checkbox"
                checked={f.useSoaSerialDateScheme}
                onChange={(e) => set('useSoaSerialDateScheme', e.target.checked)}
              />
              Use SOA Serial Date Scheme
            </label>
          </GroupRow>
        )}

        {v.servidoresPrimarios && (
          <Row
            modal
            label={
              v.servidoresPrimariosObligatorios
                ? 'Primary Name Server Addresses'
                : 'Primary Name Server Addresses (Optional)'
            }
            help={
              v.servidoresPrimariosObligatorios
                ? 'Enter the primary name server addresses to sync the zone from.'
                : 'Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.'
            }
          >
            {(id) => (
              <Textarea
                id={id}
                mono
                className={styles.area}
                spellCheck={false}
                value={f.primaryNameServerAddresses}
                onChange={(e) => set('primaryNameServerAddresses', e.target.value)}
              />
            )}
          </Row>
        )}

        {v.transferProtocol && (
          <GroupRow modal label="Zone Transfer Protocol">
            {TRANSFER_PROTOCOLS.map((p) => (
              <label key={p.value} className={styles.chk}>
                <input
                  type="radio"
                  name="addZoneTransferProtocol"
                  checked={f.zoneTransferProtocol === p.value}
                  onChange={() => set('zoneTransferProtocol', p.value)}
                />
                {p.label}
              </label>
            ))}
          </GroupRow>
        )}

        {v.tsig && (
          <Row modal label="TSIG Key Name (Optional)">
            {(id) => (
              <Select id={id} value={f.tsigKeyName} onChange={(e) => set('tsigKeyName', e.target.value)}>
                <option value="" />
                {tsigKeys.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
            )}
          </Row>
        )}

        {v.validateZone && (
          <GroupRow modal label="Zone Validation">
            <label className={styles.chk}>
              <input
                type="checkbox"
                checked={f.validateZone}
                onChange={(e) => set('validateZone', e.target.checked)}
              />
              Use <Externo href={RFC_ZONEMD}>ZONEMD</Externo> to Validate Zone
            </label>
            <div className={styles.help}>
              When enabled, the secondary zone will be validated using the ZONEMD record after every
              zone transfer. The zone will get disabled if the validation fails. The zone must be DNSSEC
              signed for the validation to work.
            </div>
          </GroupRow>
        )}

        {v.forwarderFields && (
          <>
            <GroupRow modal label="Protocol">
              {PROTOCOLOS_FORWARDER.map((p) => (
                <label key={p.value} className={styles.chk}>
                  <input
                    type="radio"
                    name="addZoneForwarderProtocol"
                    disabled={f.usarEsteServidor}
                    checked={f.forwarderProtocol === p.value}
                    onChange={() => set('forwarderProtocol', p.value)}
                  />
                  {p.label}
                </label>
              ))}
            </GroupRow>

            {/* Two help paragraphs: upstream's two, one about "This Server" and
                another about adding more forwarders later. */}
            <Row
              modal
              label="Forwarder"
              help={
                <>
                  <p>
                    When using &quot;This Server&quot;, if a record does not exists in the zone then the
                    request is forwarded to the DNS Server&apos;s resolver internally. This allows you to
                    override any record for the forwarded domain name or control its DNSSEC validation.
                  </p>
                  <p>
                    Enter a forwarder server address above. You can add more forwarders by adding FWD
                    records after the zone is added.
                  </p>
                </>
              }
            >
              {(id) => (
                <>
                  <Input
                    id={id}
                    mono
                    disabled={f.usarEsteServidor}
                    placeholder={ejemploDeForwarder(f.forwarderProtocol)}
                    value={f.usarEsteServidor ? 'this-server' : f.forwarder}
                    onChange={(e) => set('forwarder', e.target.value)}
                  />
                  <label className={styles.chk}>
                    <input
                      type="checkbox"
                      checked={f.usarEsteServidor}
                      onChange={(e) => set('usarEsteServidor', e.target.checked)}
                    />
                    Use &quot;This Server&quot;
                  </label>
                </>
              )}
            </Row>

            <GroupRow modal label="DNSSEC">
              <label className={styles.chk}>
                <input
                  type="checkbox"
                  checked={f.dnssecValidation}
                  onChange={(e) => set('dnssecValidation', e.target.checked)}
                />
                Enable DNSSEC Validation
              </label>
            </GroupRow>

            {/* "this-server" takes no proxy: upstream hides the whole block. */}
            {!f.usarEsteServidor && (
              <GroupRow modal label="Network Proxy">
                {PROXY_TYPES.map((p) => (
                  <label key={p.value} className={styles.chk}>
                    <input
                      type="radio"
                      name="addZoneProxyType"
                      checked={f.proxyType === p.value}
                      onChange={() => set('proxyType', p.value)}
                    />
                    {p.label}
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
            )}
          </>
        )}

        {/* Upstream closes this dialog with its help link (`modalAddZone`). */}
        <HelpText href="https://blog.technitium.com/2022/06/how-to-self-host-your-own-domain-name.html">
          Help: How To Self Host Your Own Domain Name
        </HelpText>
      </div>
    </Dialog>
  )
}
