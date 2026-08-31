import { useCallback, useEffect, useState } from 'react'
import {
  activateKskDnsKey,
  addPrivateKey,
  convertToNSEC,
  convertToNSEC3,
  deletePrivateKey,
  getPropiedades,
  planNxProof,
  publishAllPrivateKeys,
  retireDnsKey,
  rolloverDnsKey,
  updateDnsKeyTtl,
  updateNSEC3Params,
  updatePrivateKey,
  type Algorithm,
  type PrivateKey,
  type NxProof,
  type PropiedadesDnssec as Properties,
  type KeyKind,
} from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import { fechaMinuto as fechaCorta } from '../../../lib/dates'
import {
  ALGORITHMS,
  CURVAS_ECDSA,
  CURVAS_EDDSA,
  GENERATIONS,
  HASHES_RSA,
  NX_PROOFS,
  TAMANOS_RSA,
  KEY_TYPES,
  defaultCurve,
} from './dnssec-options'
import type { Notice, Confirmation } from '../types'
import tbl from '../../../ui/Table.module.css'
import styles from '../Zones.module.css'
import { Externo } from '../../../ui/Externo'
import { RFC_NSEC3_ITERACIONES, RFC_NSEC3_SAL } from '../references'
import frm from '../../../ui/Form.module.css'
import { Th, useOrden, type Keys, Table } from '../../../ui/Table'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalDnssecProperties` (zone.js:6799-7400). It is the project's liveliest
screen: nine different actions on the keys, each with its own alert.

Two things that are replicated and come as a surprise:

  · **Which actions a key offers depends on its state AND on its type.** A ZSK in
    any active state shows the automatic rollover field; a KSK, never.
    "Activate" only exists for a `Ready` key. And a key that is already retiring
    (`isRetiring`) offers nothing.

  · **The proof-of-non-existence "Change" button sometimes calls nobody** and
    still draws the success alert. The decision table is in
    `api/dnssec.ts::planNxProof`, tested separately.
*/


/* `sortTable('tableDnssecPropertiesPrivateKeysBody', 0..5)`. */
const KEYS: Keys<PrivateKey> = {
  keyTag: (k) => k.keyTag,
  keyType: (k) => k.keyType,
  algorithm: (k) => `${k.algorithm} (${k.algorithmNumber})`,
  state: (k) => k.state,
  changed: (k) => k.stateChangedOn,
  rollover: (k) => k.rolloverDays,
}

export function PropiedadesDnssec({
  zone,
  open,
  token,
  node = '',
  onClose,
  onConfirm,
  onChanged2,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onClose: () => void
  onConfirm: (c: Confirmation) => void
  /** The zone has to be re-read: signing and changing the proof touch its records. */
  onChanged2: () => void
}) {
  const [props, setProps] = useState<Properties | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)

  const [nxProof, setNxProof] = useState<NxProof>('NSEC')
  const [iterations, setIterations] = useState('0')
  const [saltLength, setSaltLength] = useState('0')
  const [dnsKeyTtl, setDnsKeyTtl] = useState('3600')
  const [rollovers, setRollovers] = useState<Record<number, string>>({})

  const [adding, setAnadiendo] = useState(false)
  const [newKey, setNewKey] = useState(initialNewKey)

  const load = useCallback(async () => {
    setLoading(true)
    const r = await getPropiedades(token, zone, node)
    setLoading(false)

    if (r == null) {
      setNotice({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
      return
    }

    setProps(r)
    setDnsKeyTtl(String(r.dnsKeyTtl))
    setRollovers(Object.fromEntries(r.dnssecPrivateKeys.map((k) => [k.keyTag, String(k.rolloverDays)])))

    if (r.dnssecStatus === 'SignedWithNSEC3') {
      setNxProof('NSEC3')
      setIterations(String(r.nsec3Iterations ?? 0))
      setSaltLength(String(r.nsec3SaltLength ?? 0))
    } else {
      setNxProof('NSEC')
      setIterations('0')
      setSaltLength('0')
    }
  }, [token, zone, node])

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setAnadiendo(false)
    setNewKey(initialNewKey())
    void load()
  }, [open, load])

  /** Runs it, draws the literal alert and reloads if needed. */
  async function action(
    fn: () => Promise<{ kind: string; message?: string }>,
    success: Notice,
    options: { reload?: boolean; reloadZone?: boolean } = {},
  ) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    if (options.reload !== false) await load()
    if (options.reloadZone) onChanged2()
    setNotice(success)
  }

  function saveRollover(k: PrivateKey) {
    void action(
      () => updatePrivateKey(token, zone, k.keyTag, rollovers[k.keyTag] ?? '0', node),
      {
        type: 'success',
        title: 'Updated!',
        text: 'The DNSKEY automatic rollover config was updated successfully.',
      },
      // Upstream does NOT refresh the table here: it only draws the alert.
      { reload: false },
    )
  }

  function deleteKey(k: PrivateKey) {
    onConfirm({
      title: 'Delete Private Key',
      text: `Are you sure to permanently delete the private key (${k.keyTag})?`,
      label: 'Delete',
      danger: true,
      action: () =>
        action(() => deletePrivateKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Private Key Deleted!',
          text: 'The DNSSEC private key was deleted successfully.',
        }),
    })
  }

  function activate(k: PrivateKey) {
    onConfirm({
      title: 'Activate KSK',
      text: `Are you sure you want to activate the KSK DNS Key (${k.keyTag})?`,
      label: 'Activate',
      action: () =>
        action(() => activateKskDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Activated!',
          text: 'The KSK DNS Key was activated successfully.',
        }),
    })
  }

  function rollover(k: PrivateKey) {
    onConfirm({
      title: 'Rollover DNS Key',
      text: `Are you sure you want to rollover the DNS Key (${k.keyTag})?`,
      label: 'Rollover',
      action: () =>
        action(() => rolloverDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Rollover Done!',
          text: 'The DNS Key was rolled over successfully.',
        }),
    })
  }

  function retire(k: PrivateKey) {
    onConfirm({
      title: 'Retire DNS Key',
      text: `Are you sure you want to retire the DNS Key (${k.keyTag})?`,
      label: 'Retire',
      action: () =>
        action(() => retireDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'DNS Key Retired!',
          text: 'The DNS Key was retired successfully.',
        }),
    })
  }

  function publishAll() {
    onConfirm({
      title: 'Publish All Keys',
      text: 'Are you sure you want to publish all generated DNSSEC private keys?',
      label: 'Publish',
      action: () =>
        action(() => publishAllPrivateKeys(token, zone, node), {
          type: 'success',
          title: 'Keys Published!',
          text: 'All the generated DNSSEC private keys were published successfully.',
        }),
    })
  }

  function addKey() {
    void action(
      () =>
        addPrivateKey(
          token,
          zone,
          {
            keyType: newKey.keyType,
            algorithm: newKey.algorithm,
            hashAlgorithm: newKey.hashAlgorithm,
            keySize: newKey.keySize,
            curve: newKey.curve,
            pemPrivateKey: newKey.generation === 'UseSpecified' ? newKey.pem : '',
            rolloverDays: newKey.rolloverDays,
          },
          node,
        ),
      { type: 'success', title: 'Key Added!', text: 'The DNSSEC private key was added successfully.' },
    ).then(() => {
      setAnadiendo(false)
      setNewKey(initialNewKey())
    })
  }

  function changeProof() {
    if (props == null) return

    const current: NxProof = props.dnssecStatus === 'SignedWithNSEC3' ? 'NSEC3' : 'NSEC'
    const plan = planNxProof(
      current,
      nxProof,
      { iterations: String(props.nsec3Iterations ?? 0), saltLength: String(props.nsec3SaltLength ?? 0) },
      { iterations, saltLength },
    )

    const success: Notice = {
      type: 'success',
      title: 'Proof Changed!',
      text: 'The proof of non-existence was changed successfully.',
    }

    // With no real change nobody is called… and the success alert comes out anyway.
    if (plan.action === 'ninguna') {
      setNotice(success)
      return
    }

    onConfirm({
      title: 'Change Proof of Non-Existence',
      text: 'Are you sure you want to change the proof of non-existence options for the zone?',
      label: 'Change',
      action: () =>
        action(
          () => {
            if (plan.action === 'convertToNSEC') return convertToNSEC(token, zone, node)
            if (plan.action === 'convertToNSEC3') {
              return convertToNSEC3(token, zone, plan.iterations, plan.saltLength, node)
            }
            return updateNSEC3Params(token, zone, plan.iterations, plan.saltLength, node)
          },
          success,
          { reloadZone: true },
        ),
    })
  }

  function saveTtl() {
    void action(
      () => updateDnsKeyTtl(token, zone, dnsKeyTtl, node),
      { type: 'success', title: 'TTL Updated!', text: 'The DNSKEY TTL was updated successfully.' },
      { reload: false },
    )
  }

  const keys = props?.dnssecPrivateKeys ?? []
  const { rows: visibleKeys, sort, toggle } = useOrden(KEYS, keys)
  const hasGenerated = keys.some((k) => k.state === 'Generated')
  const notes = notasDeEstado(keys)

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="wide"
      title={`DNSSEC Properties - ${zone === '.' ? '<root>' : zone}`}
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      {loading && props == null ? (
        <Loading>Loading DNSSEC properties…</Loading>
      ) : (
        <div className={styles.fields}>
          <Table
            header={
              <>
                <Th field="keyTag" sort={sort} onSort={toggle} style={{ width: 80 }}>Key Tag</Th>
                <Th field="keyType" sort={sort} onSort={toggle} style={{ width: 130 }}>Key Type</Th>
                <Th field="algorithm" sort={sort} onSort={toggle} style={{ width: 150 }}>Algorithm</Th>
                <Th field="state" sort={sort} onSort={toggle} style={{ width: 110 }}>State</Th>
                <Th field="changed" sort={sort} onSort={toggle} style={{ width: 150 }}>
                  State Changed
                </Th>
                <Th field="rollover" sort={sort} onSort={toggle} style={{ width: 150 }}>
                  Rollover (days)
                </Th>
                <th style={{ width: 190 }} />
              </>
            }
          >
            {visibleKeys.length === 0 ? (
              <tr>
                <td colSpan={7} className={tbl.noRows}>
                  No Key Found
                </td>
              </tr>
            ) : (
              visibleKeys.map((k) => (
                <KeyRow
                  key={k.keyTag}
                  privateKey={k}
                  busy={busy}
                  rollover={rollovers[k.keyTag] ?? String(k.rolloverDays)}
                  onRollover={(v) => setRollovers((r) => ({ ...r, [k.keyTag]: v }))}
                  onSaveRollover={() => saveRollover(k)}
                  onDelete={() => deleteKey(k)}
                  onActivate={() => activate(k)}
                  onRolloverAhora={() => rollover(k)}
                  onRetire={() => retire(k)}
                />
              ))
            )}
          </Table>

          {notes.map((n) => (
            <Alert key={n} type="info" title="Note!">
              {n}
            </Alert>
          ))}

          <div className={styles.acts}>
            <Button onClick={() => setAnadiendo((v) => !v)}>Add Private Key</Button>
            <Button disabled={!hasGenerated || busy} onClick={publishAll}>
              Publish All Keys
            </Button>
          </div>

          {adding && (
            <div className={styles.group}>
              <div className={styles.groupTitle}>Add Private Key</div>

              <Field label="Key Type">
                {(id) => (
                  <Select
                    id={id}
                    value={newKey.keyType}
                    onChange={(e) =>
                      setNewKey((k) => ({ ...k, keyType: e.target.value as KeyKind }))
                    }
                  >
                    {KEY_TYPES.map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>

              <Field label="Algorithm">
                {(id) => (
                  <Select
                    id={id}
                    value={newKey.algorithm}
                    onChange={(e) => {
                      const algorithm = e.target.value as Algorithm
                      setNewKey((k) => ({ ...k, algorithm, curve: defaultCurve(algorithm) }))
                    }}
                  >
                    {ALGORITHMS.map((a) => (
                      <option key={a.value} value={a.value}>
                        {a.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>

              {newKey.algorithm === 'RSA' ? (
                <Field label="Hash Algorithm">
                  {(id) => (
                    <Select
                      id={id}
                      value={newKey.hashAlgorithm}
                      onChange={(e) => setNewKey((k) => ({ ...k, hashAlgorithm: e.target.value }))}
                    >
                      {HASHES_RSA.map((h) => (
                        <option key={h.value} value={h.value}>
                          {h.label}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              ) : (
                <Field label={newKey.algorithm === 'EDDSA' ? 'EdDSA Curve' : 'ECDSA Curve'}>
                  {(id) => (
                    <Select
                      id={id}
                      value={newKey.curve}
                      onChange={(e) => setNewKey((k) => ({ ...k, curve: e.target.value }))}
                    >
                      {(newKey.algorithm === 'EDDSA' ? CURVAS_EDDSA : CURVAS_ECDSA).map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.label}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              )}

              <div className={frm.mrowCtl}>
                {GENERATIONS.map((g) => (
                  <label key={g.value} className={styles.chk}>
                    <input
                      type="radio"
                      name="addKeyGeneration"
                      checked={newKey.generation === g.value}
                      onChange={() => setNewKey((k) => ({ ...k, generation: g.value }))}
                    />
                    {g.label}
                  </label>
                ))}
              </div>

              {newKey.algorithm === 'RSA' && newKey.generation === 'Automatic' && (
                <Field label="Key Size">
                  {(id) => (
                    <div className={styles.inline}>
                      <Select
                        id={id}
                        className={styles.short}
                        value={newKey.keySize}
                        onChange={(e) => setNewKey((k) => ({ ...k, keySize: e.target.value }))}
                      >
                        {TAMANOS_RSA.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </Select>
                      <span className={styles.suffix}>bits</span>
                    </div>
                  )}
                </Field>
              )}

              {newKey.generation === 'UseSpecified' && (
                <>
                  <Field label="Private Key">
                    {(id) => (
                      <Textarea
                        placeholder={`-----BEGIN PRIVATE KEY-----
MII...
-----END PRIVATE KEY-----`}
                        id={id}
                        mono
                        className={styles.area}
                        spellCheck={false}
                        value={newKey.pem}
                        onChange={(e) => setNewKey((k) => ({ ...k, pem: e.target.value }))}
                      />
                    )}
                  </Field>
                  <div className={styles.help}>Enter a private key in PEM format.</div>
                </>
              )}

              <Field label="Automatic Key Rollover">
                {(id) => (
                  <div className={styles.inline}>
                    <Input
                      placeholder="days"
                      id={id}
                      mono
                      className={styles.short}
                      value={newKey.rolloverDays}
                      onChange={(e) => setNewKey((k) => ({ ...k, rolloverDays: e.target.value }))}
                    />
                    <span className={styles.suffix}>
                      days (valid range 0-365; default 30; set 0 to disable)
                    </span>
                  </div>
                )}
              </Field>
              <div className={styles.help}>
                The frequency at which the DNS Server must automatically rollover the key.
              </div>

              <div>
                <Button variant="primary" disabled={busy} onClick={addKey}>
                  Add Key
                </Button>
              </div>
            </div>
          )}

          <div className={styles.group}>
            <div className={styles.groupTitle}>Proof of Non-Existence</div>
            {NX_PROOFS.map((n) => (
              <label key={n.value} className={styles.chk}>
                <input
                  type="radio"
                  name="propsNxProof"
                  checked={nxProof === n.value}
                  onChange={() => setNxProof(n.value as NxProof)}
                />
                {n.label}
              </label>
            ))}

            {nxProof === 'NSEC3' && (
              <>
                <Field label="NSEC3 Iterations">
                  {(id) => (
                    <Input
                      placeholder="iterations"
                      id={id}
                      mono
                      className={styles.short}
                      value={iterations}
                      onChange={(e) => setIterations(e.target.value)}
                    />
                  )}
                </Field>
                <div className={styles.help}>
                  The number of iterations used by NSEC3 for hashing the domain names. It is
                  recommended to use 0 iterations since more iterations will increase computational
                  costs for both the DNS Server and resolver while not providing much value against
                  &quot;zone walking&quot; [<Externo href={RFC_NSEC3_ITERACIONES}>RFC 9276</Externo>].
                </div>
                <Field label="NSEC3 Salt Length">
                  {(id) => (
                    <Input
                      placeholder="length"
                      id={id}
                      mono
                      className={styles.short}
                      value={saltLength}
                      onChange={(e) => setSaltLength(e.target.value)}
                    />
                  )}
                </Field>
                <div className={styles.help}>
                  The number of bytes of random salt to generate to be used with the NSEC3 hash
                  computation. It is recommended to not use salt by setting the length to 0
                  [<Externo href={RFC_NSEC3_SAL}>RFC 9276</Externo>].
                </div>
              </>
            )}

            <div>
              <Button disabled={busy} onClick={changeProof}>
                Change
              </Button>
            </div>
          </div>

          <div className={styles.group}>
            <Field label="DNSKEY TTL">
              {(id) => (
                <div className={styles.inline}>
                  <Input
                    placeholder="ttl"
                    id={id}
                    mono
                    className={styles.short}
                    value={dnsKeyTtl}
                    onChange={(e) => setDnsKeyTtl(e.target.value)}
                  />
                  <span className={styles.suffix}>seconds</span>
                  <Button disabled={busy} onClick={saveTtl}>
                    Save
                  </Button>
                </div>
              )}
            </Field>
            <div className={styles.help}>
              The TTL value to be used for DNSKEY records. A lower value will allow quicker addition
              or rollover to a new DNS Key at the cost of increased frequency of DNSKEY queries by
              resolvers.
            </div>
          </div>
        </div>
      )}
    </Dialog>
  )
}

interface NewKey {
  keyType: KeyKind
  algorithm: Algorithm
  hashAlgorithm: string
  curve: string
  keySize: string
  generation: string
  pem: string
  rolloverDays: string
}

function initialNewKey(): NewKey {
  return {
    keyType: 'KeySigningKey',
    algorithm: 'ECDSA',
    hashAlgorithm: 'SHA256',
    curve: 'P256',
    keySize: '2048',
    generation: 'Automatic',
    pem: '',
    rolloverDays: '30',
  }
}

/**
 * Which buttons a key offers. **`isRetiring` switches everything off**: a key
 * that is already retiring takes no action at all (zone.js:6906-6930).
 */
export function keyActions(k: PrivateKey): {
  remove: boolean
  activate: boolean
  rollover: boolean
  retire: boolean
  rolloverAutomatico: boolean
} {
  const zsk = k.keyType === 'ZoneSigningKey'
  const inProgress = ['Generated', 'Published', 'Ready', 'Active'].includes(k.state)

  return {
    remove: k.state === 'Generated',
    activate: k.state === 'Ready' && !k.isRetiring,
    rollover: (k.state === 'Ready' || k.state === 'Active') && !k.isRetiring,
    retire: (k.state === 'Ready' || k.state === 'Active') && !k.isRetiring,
    // Only ZSKs have automatic rollover, and only while they are in flight.
    rolloverAutomatico: zsk && inProgress && !k.isRetiring,
  }
}

/** The three footnotes, which appear according to the keys' states. */
export function notasDeEstado(keys: PrivateKey[]): string[] {
  const notes: string[] = []

  if (keys.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Published')) {
    notes.push(
      'A "ready by" timestamp is displayed for a Key Signing Key (KSK) that is Published. Wait until then before adding its DS record to the parent zone.',
    )
  }
  if (keys.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Ready')) {
    notes.push(
      'An "active by" timestamp is displayed for a Key Signing Key (KSK) that is Ready. The key will become active automatically.',
    )
  }
  if (keys.some((k) => k.state === 'Retired' || k.state === 'Revoked')) {
    notes.push('Retired and Revoked keys are removed automatically by the DNS Server.')
  }

  return notes
}

function KeyRow({
  privateKey: k,
  busy,
  rollover,
  onRollover,
  onSaveRollover,
  onDelete,
  onActivate,
  onRolloverAhora,
  onRetire,
}: {
  privateKey: PrivateKey
  busy: boolean
  rollover: string
  onRollover: (v: string) => void
  onSaveRollover: () => void
  onDelete: () => void
  onActivate: () => void
  onRolloverAhora: () => void
  onRetire: () => void
}) {
  const a = keyActions(k)

  return (
    <tr>
      <td className={styles.mono}>{k.keyTag}</td>
      <td>{k.keyType}</td>
      <td>
        {k.algorithm} ({k.algorithmNumber})
      </td>
      <td>
        {k.state}
        {k.state === 'Active' && k.isRetiring ? ' (retiring)' : ''}
      </td>
      <td className={styles.mono} style={{ fontSize: 11.5 }}>
        {fechaCorta(k.stateChangedOn)}
        {k.stateReadyBy != null && <div>(ready by: {fechaCorta(k.stateReadyBy)})</div>}
        {k.stateReadyBy == null && k.stateActiveBy != null && (
          <div>(active by: {fechaCorta(k.stateActiveBy)})</div>
        )}
      </td>
      <td>
        {a.rolloverAutomatico ? (
          <div className={styles.inline}>
            <Input
              mono
              className={styles.short}
              aria-label={`Rollover days for ${k.keyTag}`}
              placeholder="days"
              value={rollover}
              onChange={(e) => onRollover(e.target.value)}
            />
            <Button size="sm" disabled={busy} onClick={onSaveRollover}>
              Save
            </Button>
          </div>
        ) : (
          '—'
        )}
      </td>
      <td className={tbl.actionsCell}>
        <div className={tbl.actions}>
          {a.remove && (
            <Button size="sm" disabled={busy} onClick={onDelete}>
              Delete
            </Button>
          )}
          {a.activate && (
            <Button size="sm" disabled={busy} onClick={onActivate}>
              Activate
            </Button>
          )}
          {a.rollover && (
            <Button size="sm" disabled={busy} onClick={onRolloverAhora}>
              Rollover
            </Button>
          )}
          {a.retire && (
            <Button size="sm" disabled={busy} onClick={onRetire}>
              Retire
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}
