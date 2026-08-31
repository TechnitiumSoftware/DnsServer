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
import type { Aviso, Confirmacion } from '../tipos'
import tbl from '../../../ui/Table.module.css'
import styles from '../Zones.module.css'
import { Externo } from '../../../ui/Externo'
import { RFC_NSEC3_ITERACIONES, RFC_NSEC3_SAL } from '../referencias'
import frm from '../../../ui/Form.module.css'
import { Th, useOrden, type Claves, Tabla } from '../../../ui/Table'
import { avisoDeFallo } from '../../../lib/aviso'
import { Avisador } from '../../../ui/Avisador'

/*
`modalDnssecProperties` (zone.js:6799-7400). Es la pantalla más viva del
proyecto: nueve acciones distintas sobre las claves, cada una con su aviso.

Dos cosas que se replican y sorprenden:

  · **Qué acciones ofrece una clave depende de su estado Y de su tipo.** Una ZSK
    en cualquier estado activo enseña el campo de rollover automático; una KSK,
    nunca. «Activate» sólo existe para una clave `Ready`. Y una clave que ya se
    está retirando (`isRetiring`) no ofrece nada.

  · **El botón «Change» de la prueba de no-existencia a veces no llama a nadie**
    y aun así pinta el aviso de éxito. La tabla de decisión está en
    `api/dnssec.ts::planNxProof`, probada aparte.
*/


/* `sortTable('tableDnssecPropertiesPrivateKeysBody', 0..5)`. */
const CLAVES: Claves<ClavePrivada> = {
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
  onConfirmar: (c: Confirmacion) => void
  /** La zona hay que releerla: firmar y cambiar la prueba tocan sus registros. */
  onCambio: () => void
}) {
  const [props, setProps] = useState<Propiedades | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cargando, setCargando] = useState(false)
  const [ocupado, setOcupado] = useState(false)

  const [nxProof, setNxProof] = useState<NxProof>('NSEC')
  const [iterations, setIterations] = useState('0')
  const [saltLength, setSaltLength] = useState('0')
  const [dnsKeyTtl, setDnsKeyTtl] = useState('3600')
  const [rollovers, setRollovers] = useState<Record<number, string>>({})

  const [anadiendo, setAnadiendo] = useState(false)
  const [nuevaClave, setNuevaClave] = useState(claveNuevaInicial)

  const cargar = useCallback(async () => {
    setCargando(true)
    const r = await getPropiedades(token, zone, node)
    setCargando(false)

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

  /** Ejecuta, pinta el aviso literal y recarga si hace falta. */
  async function accion(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
    opciones: { recargar?: boolean; recargarZona?: boolean } = {},
  ) {
    setOcupado(true)
    const outcome = await fn()
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    if (opciones.recargar !== false) await cargar()
    if (opciones.recargarZona) onCambio()
    setAviso(exito)
  }

  function guardarRollover(k: ClavePrivada) {
    void accion(
      () => updatePrivateKey(token, zone, k.keyTag, rollovers[k.keyTag] ?? '0', node),
      {
        type: 'success',
        title: 'Updated!',
        text: 'The DNSKEY automatic rollover config was updated successfully.',
      },
      // Upstream NO refresca la tabla aquí: sólo pinta el aviso.
      { recargar: false },
    )
  }

  function borrarClave(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Delete Private Key',
      texto: `Are you sure to permanently delete the private key (${k.keyTag})?`,
      etiqueta: 'Delete',
      peligro: true,
      accion: () =>
        accion(() => deletePrivateKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Private Key Deleted!',
          text: 'The DNSSEC private key was deleted successfully.',
        }),
    })
  }

  function activar(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Activate KSK',
      texto: `Are you sure you want to activate the KSK DNS Key (${k.keyTag})?`,
      etiqueta: 'Activate',
      accion: () =>
        accion(() => activateKskDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Activated!',
          text: 'The KSK DNS Key was activated successfully.',
        }),
    })
  }

  function rollover(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Rollover DNS Key',
      texto: `Are you sure you want to rollover the DNS Key (${k.keyTag})?`,
      etiqueta: 'Rollover',
      accion: () =>
        accion(() => rolloverDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'Rollover Done!',
          text: 'The DNS Key was rolled over successfully.',
        }),
    })
  }

  function retirar(k: ClavePrivada) {
    onConfirmar({
      titulo: 'Retire DNS Key',
      texto: `Are you sure you want to retire the DNS Key (${k.keyTag})?`,
      etiqueta: 'Retire',
      accion: () =>
        accion(() => retireDnsKey(token, zone, k.keyTag, node), {
          type: 'success',
          title: 'DNS Key Retired!',
          text: 'The DNS Key was retired successfully.',
        }),
    })
  }

  function publicarTodas() {
    onConfirmar({
      titulo: 'Publish All Keys',
      texto: 'Are you sure you want to publish all generated DNSSEC private keys?',
      etiqueta: 'Publish',
      accion: () =>
        accion(() => publishAllPrivateKeys(token, zone, node), {
          type: 'success',
          title: 'Keys Published!',
          text: 'All the generated DNSSEC private keys were published successfully.',
        }),
    })
  }

  function anadirClave() {
    void accion(
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
            pemPrivateKey: nuevaClave.generacion === 'UseSpecified' ? nuevaClave.pem : '',
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

    const actual: NxProof = props.dnssecStatus === 'SignedWithNSEC3' ? 'NSEC3' : 'NSEC'
    const plan = planNxProof(
      actual,
      nxProof,
      { iterations: String(props.nsec3Iterations ?? 0), saltLength: String(props.nsec3SaltLength ?? 0) },
      { iterations, saltLength },
    )

    const exito: Aviso = {
      type: 'success',
      title: 'Proof Changed!',
      text: 'The proof of non-existence was changed successfully.',
    }

    // Sin cambio real no se llama a nadie… y el aviso de éxito sale igual.
    if (plan.accion === 'ninguna') {
      setAviso(exito)
      return
    }

    onConfirmar({
      titulo: 'Change Proof of Non-Existence',
      texto: 'Are you sure you want to change the proof of non-existence options for the zone?',
      etiqueta: 'Change',
      accion: () =>
        accion(
          () => {
            if (plan.accion === 'convertToNSEC') return convertToNSEC(token, zone, node)
            if (plan.accion === 'convertToNSEC3') {
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
    void accion(
      () => updateDnsKeyTtl(token, zone, dnsKeyTtl, node),
      { type: 'success', title: 'TTL Updated!', text: 'The DNSKEY TTL was updated successfully.' },
      { recargar: false },
    )
  }

  const claves = props?.dnssecPrivateKeys ?? []
  const { filas: clavesVisibles, orden, alternar } = useOrden(CLAVES, claves)
  const hayGeneradas = claves.some((k) => k.state === 'Generated')
  const notas = notasDeEstado(claves)

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      tamano="ancho"
      title={`DNSSEC Properties - ${zone === '.' ? '<root>' : zone}`}
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {cargando && props == null ? (
        <Loading>Loading DNSSEC properties…</Loading>
      ) : (
        <div className={styles.campos}>
          <Tabla
            cabecera={
              <>
                <Th campo="keyTag" orden={orden} onOrdenar={alternar} style={{ width: 80 }}>Key Tag</Th>
                <Th campo="keyType" orden={orden} onOrdenar={alternar} style={{ width: 130 }}>Key Type</Th>
                <Th campo="algorithm" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>Algorithm</Th>
                <Th campo="state" orden={orden} onOrdenar={alternar} style={{ width: 110 }}>State</Th>
                <Th campo="changed" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>
                  State Changed
                </Th>
                <Th campo="rollover" orden={orden} onOrdenar={alternar} style={{ width: 150 }}>
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
                  clave={k}
                  ocupado={ocupado}
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
          </Tabla>

          {notas.map((n) => (
            <Alert key={n} type="info" title="Note!">
              {n}
            </Alert>
          ))}

          <div className={styles.acts}>
            <Button onClick={() => setAnadiendo((v) => !v)}>Add Private Key</Button>
            <Button disabled={!hayGeneradas || ocupado} onClick={publicarTodas}>
              Publish All Keys
            </Button>
          </div>

          {anadiendo && (
            <div className={styles.grupo}>
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
                      <option key={t.valor} value={t.valor}>
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
                      <option key={a.valor} value={a.valor}>
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
                        <option key={h.valor} value={h.valor}>
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
                        <option key={c.valor} value={c.valor}>
                          {c.etiqueta}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              )}

              <div className={frm.mrowCtl}>
                {GENERACIONES.map((g) => (
                  <label key={g.valor} className={styles.chk}>
                    <input
                      type="radio"
                      name="addKeyGeneration"
                      checked={nuevaClave.generacion === g.valor}
                      onChange={() => setNuevaClave((k) => ({ ...k, generacion: g.valor }))}
                    />
                    {g.etiqueta}
                  </label>
                ))}
              </div>

              {nuevaClave.algorithm === 'RSA' && nuevaClave.generacion === 'Automatic' && (
                <Field label="Key Size">
                  {(id) => (
                    <div className={styles.enLinea}>
                      <Select
                        id={id}
                        className={styles.corto}
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

              {nuevaClave.generacion === 'UseSpecified' && (
                <>
                  <Field label="Private Key">
                    {(id) => (
                      <Textarea
                        id={id}
                        mono
                        className={styles.area}
                        spellCheck={false}
                        value={nuevaClave.pem}
                        onChange={(e) => setNuevaClave((k) => ({ ...k, pem: e.target.value }))}
                      />
                    )}
                  </Field>
                  <div className={styles.ayuda}>Enter a private key in PEM format.</div>
                </>
              )}

              <Field label="Automatic Key Rollover">
                {(id) => (
                  <div className={styles.enLinea}>
                    <Input
                      id={id}
                      mono
                      className={styles.corto}
                      value={nuevaClave.rolloverDays}
                      onChange={(e) => setNuevaClave((k) => ({ ...k, rolloverDays: e.target.value }))}
                    />
                    <span className={styles.sufijo}>
                      days (valid range 0-365; default 30; set 0 to disable)
                    </span>
                  </div>
                )}
              </Field>
              <div className={styles.ayuda}>
                The frequency at which the DNS Server must automatically rollover the key.
              </div>

              <div>
                <Button variant="primary" disabled={ocupado} onClick={anadirClave}>
                  Add Key
                </Button>
              </div>
            </div>
          )}

          <div className={styles.grupo}>
            <div className={styles.grupoTit}>Proof of Non-Existence</div>
            {PRUEBAS_NX.map((n) => (
              <label key={n.valor} className={styles.chk}>
                <input
                  type="radio"
                  name="propsNxProof"
                  checked={nxProof === n.valor}
                  onChange={() => setNxProof(n.valor as NxProof)}
                />
                {n.etiqueta}
              </label>
            ))}

            {nxProof === 'NSEC3' && (
              <>
                <Field label="NSEC3 Iterations">
                  {(id) => (
                    <Input
                      id={id}
                      mono
                      className={styles.corto}
                      value={iterations}
                      onChange={(e) => setIterations(e.target.value)}
                    />
                  )}
                </Field>
                <div className={styles.ayuda}>
                  The number of iterations used by NSEC3 for hashing the domain names. It is
                  recommended to use 0 iterations since more iterations will increase computational
                  costs for both the DNS Server and resolver while not providing much value against
                  &quot;zone walking&quot; [<Externo href={RFC_NSEC3_ITERACIONES}>RFC 9276</Externo>].
                </div>
                <Field label="NSEC3 Salt Length">
                  {(id) => (
                    <Input
                      id={id}
                      mono
                      className={styles.corto}
                      value={saltLength}
                      onChange={(e) => setSaltLength(e.target.value)}
                    />
                  )}
                </Field>
                <div className={styles.ayuda}>
                  The number of bytes of random salt to generate to be used with the NSEC3 hash
                  computation. It is recommended to not use salt by setting the length to 0
                  [<Externo href={RFC_NSEC3_SAL}>RFC 9276</Externo>].
                </div>
              </>
            )}

            <div>
              <Button disabled={ocupado} onClick={cambiarPrueba}>
                Change
              </Button>
            </div>
          </div>

          <div className={styles.grupo}>
            <Field label="DNSKEY TTL">
              {(id) => (
                <div className={styles.enLinea}>
                  <Input
                    id={id}
                    mono
                    className={styles.corto}
                    value={dnsKeyTtl}
                    onChange={(e) => setDnsKeyTtl(e.target.value)}
                  />
                  <span className={styles.sufijo}>seconds</span>
                  <Button disabled={ocupado} onClick={guardarTtl}>
                    Save
                  </Button>
                </div>
              )}
            </Field>
            <div className={styles.ayuda}>
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
  generacion: string
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
    generacion: 'Automatic',
    pem: '',
    rolloverDays: '30',
  }
}

/**
 * Qué botones ofrece una clave. **`isRetiring` lo apaga todo**: una clave que
 * ya se está retirando no admite ninguna acción (zone.js:6906-6930).
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
    // Sólo las ZSK tienen rollover automático, y sólo mientras están en curso.
    rolloverAutomatico: zsk && enCurso && !k.isRetiring,
  }
}

/** Las tres notas al pie, que aparecen según los estados de las claves. */
export function notasDeEstado(claves: ClavePrivada[]): string[] {
  const notas: string[] = []

  if (claves.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Published')) {
    notas.push(
      'A "ready by" timestamp is displayed for a Key Signing Key (KSK) that is Published. Wait until then before adding its DS record to the parent zone.',
    )
  }
  if (claves.some((k) => k.keyType === 'KeySigningKey' && k.state === 'Ready')) {
    notas.push(
      'An "active by" timestamp is displayed for a Key Signing Key (KSK) that is Ready. The key will become active automatically.',
    )
  }
  if (claves.some((k) => k.state === 'Retired' || k.state === 'Revoked')) {
    notas.push('Retired and Revoked keys are removed automatically by the DNS Server.')
  }

  return notas
}

function FilaClave({
  clave: k,
  ocupado,
  rollover,
  onRollover,
  onGuardarRollover,
  onBorrar,
  onActivar,
  onRolloverAhora,
  onRetirar,
}: {
  clave: ClavePrivada
  ocupado: boolean
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
              className={styles.corto}
              aria-label={`Rollover days for ${k.keyTag}`}
              placeholder="days"
              value={rollover}
              onChange={(e) => onRollover(e.target.value)}
            />
            <Button size="sm" disabled={ocupado} onClick={onGuardarRollover}>
              Save
            </Button>
          </div>
        ) : (
          '—'
        )}
      </td>
      <td className={tbl.celdaAcciones}>
        <div className={tbl.acciones}>
          {a.borrar && (
            <Button size="sm" disabled={ocupado} onClick={onBorrar}>
              Delete
            </Button>
          )}
          {a.activar && (
            <Button size="sm" disabled={ocupado} onClick={onActivar}>
              Activate
            </Button>
          )}
          {a.rollover && (
            <Button size="sm" disabled={ocupado} onClick={onRolloverAhora}>
              Rollover
            </Button>
          )}
          {a.retirar && (
            <Button size="sm" disabled={ocupado} onClick={onRetirar}>
              Retire
            </Button>
          )}
        </div>
      </td>
    </tr>
  )
}
