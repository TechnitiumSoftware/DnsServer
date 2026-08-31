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
  type Algoritmo,
  type ClavePrivada,
  type NxProof,
  type PropiedadesDnssec as Propiedades,
  type TipoClave,
} from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import { fechaMinuto as fechaCorta } from '../../../lib/fechas'
import {
  ALGORITMOS,
  CURVAS_ECDSA,
  CURVAS_EDDSA,
  GENERACIONES,
  HASHES_RSA,
  PRUEBAS_NX,
  TAMANOS_RSA,
  TIPOS_CLAVE,
  curvaPorDefecto,
} from './dnssec-opciones'
import type { Aviso, Confirmation } from '../tipos'
import tbl from '../../../ui/Table.module.css'
import styles from '../Zones.module.css'
import { Externo } from '../../../ui/Externo'
import { RFC_NSEC3_ITERACIONES, RFC_NSEC3_SAL } from '../referencias'
import frm from '../../../ui/Form.module.css'
import { Th, useOrden, type Keys, Table } from '../../../ui/Table'
import { avisoDeFallo } from '../../../lib/aviso'
import { Avisador } from '../../../ui/Avisador'

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
const KEYS: Keys<ClavePrivada> = {
  keyTag: (k) => k.keyTag,
  keyType: (k) => k.keyType,
  algorithm: (k) => `${k.algorithm} (${k.algorithmNumber})`,
  state: (k) => k.state,
  changed: (k) => k.stateChangedOn,
  rollover: (k) => k.rolloverDays,
}

export function PropiedadesDnssec({
  zone,
  abierto,
  token,
  node = '',
  onCerrar,
  onConfirmar,
  onCambio,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onConfirmar: (c: Confirmation) => void
  /** The zone has to be re-read: signing and changing the proof touch its records. */
  onCambio: () => void
}) {
  const [props, setProps] = useState<Propiedades | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)

  const [nxProof, setNxProof] = useState<NxProof>('NSEC')
  const [iterations, setIterations] = useState('0')
  const [saltLength, setSaltLength] = useState('0')
  const [dnsKeyTtl, setDnsKeyTtl] = useState('3600')
  const [rollovers, setRollovers] = useState<Record<number, string>>({})

  const [anadiendo, setAnadiendo] = useState(false)
  const [nuevaClave, setNuevaClave] = useState(claveNuevaInicial)

  const cargar = useCallback(async () => {
    setLoading(true)
    const r = await getPropiedades(token, zone, node)
    setLoading(false)

    if (r == null) {
      setAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
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
    if (!abierto) return
    setAviso(null)
    setAnadiendo(false)
    setNuevaClave(claveNuevaInicial())
    void cargar()
  }, [abierto, cargar])

  /** Runs it, draws the literal alert and reloads if needed. */
  async function action(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
    options: { recargar?: boolean; recargarZona?: boolean } = {},
  ) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    if (options.recargar !== false) await cargar()
    if (options.recargarZona) onCambio()
    setAviso(exito)
  }

  function guardarRollover(k: ClavePrivada) {
    void action(
      () => updatePrivateKey(token, zone, k.keyTag, rollovers[k.keyTag] ?? '0', node),
      {
        type: 'success',
        title: 'Updated!',
        text: 'The DNSKEY automatic rollover config was updated successfully.',
      },
      // Upstream does NOT refresh the table here: it only draws the alert.
      { recargar: false },
    )
  }

  function borrarClave(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Delete Private Key',
      text: `Are you sure to permanently delete the private key (${k.keyTag})?`,
      etiqueta: 'Delete',
      peligro: true,
      action: () =>
        action(() => deletePrivateKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Private Key Deleted!',
          text: 'The DNSSEC private key was deleted successfully.',
        }),
    })
  }

  function activar(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Activate KSK',
      text: `Are you sure you want to activate the KSK DNS Key (${k.keyTag})?`,
      etiqueta: 'Activate',
      action: () =>
        action(() => activateKskDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Activated!',
          text: 'The KSK DNS Key was activated successfully.',
        }),
    })
  }

  function rollover(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Rollover DNS Key',
      text: `Are you sure you want to rollover the DNS Key (${k.keyTag})?`,
      etiqueta: 'Rollover',
      action: () =>
        action(() => rolloverDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Rollover Done!',
          text: 'The DNS Key was rolled over successfully.',
        }),
    })
  }

  function retirar(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Retire DNS Key',
      text: `Are you sure you want to retire the DNS Key (${k.keyTag})?`,
      etiqueta: 'Retire',
      action: () =>
        action(() => retireDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'DNS Key Retired!',
          text: 'The DNS Key was retired successfully.',
        }),
    })
  }

  function publicarTodas() {
    onConfirmar({
      titulo: 'Publish All Keys',
      text: 'Are you sure you want to publish all generated DNSSEC private keys?',
      etiqueta: 'Publish',
      action: () =>
        action(() => publishAllPrivateKeys(token, zone, node), {
          type: 'success',
          title: 'Keys Published!',
          text: 'All the generated DNSSEC private keys were published successfully.',
        }),
    })
  }

  function anadirClave() {
    void action(
      () =>
        addPrivateKey(
          token,
          zone,
          {
            keyType: nuevaClave.keyType,
            algorithm: nuevaClave.algorithm,
            hashAlgorithm: nuevaClave.hashAlgorithm,
            keySize: nuevaClave.keySize,
            curve: nuevaClave.curve,
            pemPrivateKey: nuevaClave.generation === 'UseSpecified' ? nuevaClave.pem : '',
            rolloverDays: nuevaClave.rolloverDays,
          },
          node,
        ),
      { type: 'success', title: 'Key Added!', text: 'The DNSSEC private key was added successfully.' },
    ).then(() => {
      setAnadiendo(false)
      setNuevaClave(claveNuevaInicial())
    })
  }

  function cambiarPrueba() {
    if (props == null) return

    const current: NxProof = props.dnssecStatus === 'SignedWithNSEC3' ? 'NSEC3' : 'NSEC'
    const plan = planNxProof(
      current,
      nxProof,
      { iterations: String(props.nsec3Iterations ?? 0), saltLength: String(props.nsec3SaltLength ?? 0) },
      { iterations, saltLength },
    )

    const exito: Aviso = {
      type: 'success',
      title: 'Proof Changed!',
      text: 'The proof of non-existence was changed successfully.',
    }

    // With no real change nobody is called… and the success alert comes out anyway.
    if (plan.action === 'ninguna') {
      setAviso(exito)
      return
    }

    onConfirmar({
      titulo: 'Change Proof of Non-Existence',
      text: 'Are you sure you want to change the proof of non-existence options for the zone?',
      etiqueta: 'Change',
      action: () =>
        action(
          () => {
            if (plan.action === 'convertToNSEC') return convertToNSEC(token, zone, node)
            if (plan.action === 'convertToNSEC3') {
              return convertToNSEC3(token, zone, plan.iterations, plan.saltLength, node)
            }
            return updateNSEC3Params(token, zone, plan.iterations, plan.saltLength, node)
          },
          exito,
          { recargarZona: true },
        ),
    })
  }

  function guardarTtl() {
    void action(
      () => updateDnsKeyTtl(token, zone, dnsKeyTtl, node),
      { type: 'success', title: 'TTL Updated!', text: 'The DNSKEY TTL was updated successfully.' },
      { recargar: false },
    )
  }

  const keys = props?.dnssecPrivateKeys ?? []
  const { rows: clavesVisibles, orden, alternar } = useOrden(KEYS, keys)
  const hayGeneradas = keys.some((k) => k.state === 'Generated')
  const notas = notasDeEstado(keys)

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      size="wide"
      title={`DNSSEC Properties - ${zone === '.' ? '<root>' : zone}`}
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {loading && props == null ? (
        <Loading>Loading DNSSEC properties…</Loading>
      ) : (
        <div className={styles.fields}>
          <Table
            header={
              <>
                <Th field="keyTag" orden={orden} onOrdenar={alternar} style={{ width: 80 }}>Key Tag</Th>
                <Th field="keyType" orden={orden} onOrdenar={alternar} style={{ width: 130 }}>Key Type</Th>
                <Th field="algorithm" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>Algorithm</Th>
                <Th field="state" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>State</Th>
                <Th field="changed" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>
                  State Changed
                </Th>
                <Th field="rollover" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>
                  Rollover (days)
                </Th>
                <th style={{ width: 190 }} />
              </>
            }
          >
            {clavesVisibles.length === 0 ? (
              <tr>
                <td colSpan={7} className={tbl.sinFilas}>
                  No Key Found
                </td>
              </tr>
            ) : (
              clavesVisibles.map((k) => (
                <FilaClave
                  key={k.keyTag}
                  privateKey={k}
                  busy={busy}
                  rollover={rollovers[k.keyTag] ?? String(k.rolloverDays)}
                  onRollover={(v) => setRollovers((r) => ({ ...r, [k.keyTag]: v }))}
                  onGuardarRollover={() => guardarRollover(k)}
                  onBorrar={() => borrarClave(k)}
                  onActivar={() => activar(k)}
                  onRolloverAhora={() => rollover(k)}
                  onRetirar={() => retirar(k)}
                />
              ))
            )}
          </Table>

          {notas.map((n) => (
            <Alert key={n} type="info" title="Note!">
              {n}
            </Alert>
          ))}

          <div className={styles.acts}>
            <Button onClick={() => setAnadiendo((v) => !v)}>Add Private Key</Button>
            <Button disabled={!hayGeneradas || busy} onClick={publicarTodas}>
              Publish All Keys
            </Button>
          </div>

          {anadiendo && (
            <div className={styles.group}>
              <div className={styles.grupoTit}>Add Private Key</div>

              <Field label="Key Type">
                {(id) => (
                  <Select
                    id={id}
                    value={nuevaClave.keyType}
                    onChange={(e) =>
                      setNuevaClave((k) => ({ ...k, keyType: e.target.value as TipoClave }))
                    }
                  >
                    {TIPOS_CLAVE.map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.etiqueta}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>

              <Field label="Algorithm">
                {(id) => (
                  <Select
                    id={id}
                    value={nuevaClave.algorithm}
                    onChange={(e) => {
                      const algorithm = e.target.value as Algoritmo
                      setNuevaClave((k) => ({ ...k, algorithm, curve: curvaPorDefecto(algorithm) }))
                    }}
                  >
                    {ALGORITMOS.map((a) => (
                      <option key={a.value} value={a.value}>
                        {a.etiqueta}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>

              {nuevaClave.algorithm === 'RSA' ? (
                <Field label="Hash Algorithm">
                  {(id) => (
                    <Select
                      id={id}
                      value={nuevaClave.hashAlgorithm}
                      onChange={(e) => setNuevaClave((k) => ({ ...k, hashAlgorithm: e.target.value }))}
                    >
                      {HASHES_RSA.map((h) => (
                        <option key={h.value} value={h.value}>
                          {h.etiqueta}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              ) : (
                <Field label={nuevaClave.algorithm === 'EDDSA' ? 'EdDSA Curve' : 'ECDSA Curve'}>
                  {(id) => (
                    <Select
                      id={id}
                      value={nuevaClave.curve}
                      onChange={(e) => setNuevaClave((k) => ({ ...k, curve: e.target.value }))}
                    >
                      {(nuevaClave.algorithm === 'EDDSA' ? CURVAS_EDDSA : CURVAS_ECDSA).map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.etiqueta}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              )}

              <div className={frm.mrowCtl}>
                {GENERACIONES.map((g) => (
                  <label key={g.value} className={styles.chk}>
                    <input
                      type="radio"
                      name="addKeyGeneration"
                      checked={nuevaClave.generation === g.value}
                      onChange={() => setNuevaClave((k) => ({ ...k, generation: g.value }))}
                    />
                    {g.etiqueta}
                  </label>
                ))}
              </div>

              {nuevaClave.algorithm === 'RSA' && nuevaClave.generation === 'Automatic' && (
                <Field label="Key Size">
                  {(id) => (
                    <div className={styles.enLinea}>
                      <Select
                        id={id}
                        className={styles.short}
                        value={nuevaClave.keySize}
                        onChange={(e) => setNuevaClave((k) => ({ ...k, keySize: e.target.value }))}
                      >
                        {TAMANOS_RSA.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </Select>
                      <span className={styles.sufijo}>bits</span>
                    </div>
                  )}
                </Field>
              )}

              {nuevaClave.generation === 'UseSpecified' && (
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
                        value={nuevaClave.pem}
                        onChange={(e) => setNuevaClave((k) => ({ ...k, pem: e.target.value }))}
                      />
                    )}
                  </Field>
                  <div className={styles.help}>Enter a private key in PEM format.</div>
                </>
              )}

              <Field label="Automatic Key Rollover">
                {(id) => (
                  <div className={styles.enLinea}>
                    <Input
                      placeholder="days"
                      id={id}
                      mono
                      className={styles.short}
                      value={nuevaClave.rolloverDays}
                      onChange={(e) => setNuevaClave((k) => ({ ...k, rolloverDays: e.target.value }))}
                    />
                    <span className={styles.sufijo}>
                      days (valid range 0-365; default 30; set 0 to disable)
                    </span>
                  </div>
                )}
              </Field>
              <div className={styles.help}>
                The frequency at which the DNS Server must automatically rollover the key.
              </div>

              <div>
                <Button variant="primary" disabled={busy} onClick={anadirClave}>
                  Add Key
                </Button>
              </div>
            </div>
          )}

          <div className={styles.group}>
            <div className={styles.grupoTit}>Proof of Non-Existence</div>
            {PRUEBAS_NX.map((n) => (
              <label key={n.value} className={styles.chk}>
                <input
                  type="radio"
                  name="propsNxProof"
                  checked={nxProof === n.value}
                  onChange={() => setNxProof(n.value as NxProof)}
                />
                {n.etiqueta}
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
              <Button disabled={busy} onClick={cambiarPrueba}>
                Change
              </Button>
            </div>
          </div>

          <div className={styles.group}>
            <Field label="DNSKEY TTL">
              {(id) => (
                <div className={styles.enLinea}>
                  <Input
                    placeholder="ttl"
                    id={id}
                    mono
                    className={styles.short}
                    value={dnsKeyTtl}
                    onChange={(e) => setDnsKeyTtl(e.target.value)}
                  />
                  <span className={styles.sufijo}>seconds</span>
                  <Button disabled={busy} onClick={guardarTtl}>
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

interface ClaveNueva {
  keyType: TipoClave
  algorithm: Algoritmo
  hashAlgorithm: string
  curve: string
  keySize: string
  generation: string
  pem: string
  rolloverDays: string
}

function claveNuevaInicial(): ClaveNueva {
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
export function accionesDeClave(k: ClavePrivada): {
  borrar: boolean
  activar: boolean
  rollover: boolean
  retirar: boolean
  rolloverAutomatico: boolean
} {
  const zsk = k.keyType === 'ZoneSigningKey'
  const enCurso = ['Generated', 'Published', 'Ready', 'Active'].includes(k.state)

  return {
    borrar: k.state === 'Generated',
    activar: k.state === 'Ready' && !k.isRetiring,
    rollover: (k.state === 'Ready' || k.state === 'Active') && !k.isRetiring,
    retirar: (k.state === 'Ready' || k.state === 'Active') && !k.isRetiring,
    // Only ZSKs have automatic rollover, and only while they are in flight.
    rolloverAutomatico: zsk && enCurso && !k.isRetiring,
  }
}

/** The three footnotes, which appear according to the keys' states. */
export function notasDeEstado(keys: ClavePrivada[]): string[] {
  const notas: string[] = []

  if (keys.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Published')) {
    notas.push(
      'A "ready by" timestamp is displayed for a Key Signing Key (KSK) that is Published. Wait until then before adding its DS record to the parent zone.',
    )
  }
  if (keys.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Ready')) {
    notas.push(
      'An "active by" timestamp is displayed for a Key Signing Key (KSK) that is Ready. The key will become active automatically.',
    )
  }
  if (keys.some((k) => k.state === 'Retired' || k.state === 'Revoked')) {
    notas.push('Retired and Revoked keys are removed automatically by the DNS Server.')
  }

  return notas
}

function FilaClave({
  privateKey: k,
  busy,
  rollover,
  onRollover,
  onGuardarRollover,
  onBorrar,
  onActivar,
  onRolloverAhora,
  onRetirar,
}: {
  privateKey: ClavePrivada
  busy: boolean
  rollover: string
  onRollover: (v: string) => void
  onGuardarRollover: () => void
  onBorrar: () => void
  onActivar: () => void
  onRolloverAhora: () => void
  onRetirar: () => void
}) {
  const a = accionesDeClave(k)

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
          <div className={styles.enLinea}>
            <Input
              mono
              className={styles.short}
              aria-label={`Rollover days for ${k.keyTag}`}
              placeholder="days"
              value={rollover}
              onChange={(e) => onRollover(e.target.value)}
            />
            <Button size="sm" disabled={busy} onClick={onGuardarRollover}>
              Save
            </Button>
          </div>
        ) : (
          '—'
        )}
      </td>
      <td className={tbl.celdaAcciones}>
        <div className={tbl.actions}>
          {a.borrar && (
            <Button size="sm" disabled={busy} onClick={onBorrar}>
              Delete
            </Button>
          )}
          {a.activar && (
            <Button size="sm" disabled={busy} onClick={onActivar}>
              Activate
            </Button>
          )}
          {a.rollover && (
            <Button size="sm" disabled={busy} onClick={onRolloverAhora}>
              Rollover
            </Button>
          )}
          {a.retirar && (
            <Button size="sm" disabled={busy} onClick={onRetirar}>
              Retire
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}
