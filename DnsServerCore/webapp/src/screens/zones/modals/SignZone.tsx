import { useEffect, useState } from 'react'
import { signZone, type Algorithm, type NxProof } from '../../../api/dnssec'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import {
  ALGORITHMS,
  CURVAS_ECDSA,
  CURVAS_EDDSA,
  GENERACIONES,
  HASHES_RSA,
  PRUEBAS_NX,
  TAMANOS_RSA,
  curvaPorDefecto,
} from './dnssec-options'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { HelpText, Externo } from '../../../ui/Externo'
import { AYUDA_DNSSEC, RFC_NSEC3_ITERACIONES, RFC_NSEC3_SAL } from '../references'
import { GroupRow } from '../../../ui/Form'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalDnssecSignZone` (zone.js:6539 and 6578).

The initial values are NOT those of an empty form: ECDSA with P256, automatic KSK
and ZSK, NSEC, TTL 3600 and a ZSK rollover every 30 days. And RSA's default sizes
are **different between KSK and ZSK** —2048 and 1280— which is the kind of detail
that gets lost when "cleaning up" a form.
*/

interface Formulario {
  algorithm: Algorithm
  hashAlgorithm: string
  curve: string
  kskGeneration: string
  kskKeySize: string
  pemKskPrivateKey: string
  zskGeneration: string
  zskKeySize: string
  pemZskPrivateKey: string
  nxProof: NxProof
  iterations: string
  saltLength: string
  dnsKeyTtl: string
  zskRolloverDays: string
}

function inicial(): Formulario {
  return {
    algorithm: 'ECDSA',
    hashAlgorithm: 'SHA256',
    curve: 'P256',
    kskGeneration: 'Automatic',
    kskKeySize: '2048',
    pemKskPrivateKey: '',
    zskGeneration: 'Automatic',
    zskKeySize: '1280',
    pemZskPrivateKey: '',
    nxProof: 'NSEC',
    iterations: '0',
    saltLength: '0',
    dnsKeyTtl: '3600',
    zskRolloverDays: '30',
  }
}

export function SignZone({
  zone,
  open,
  token,
  node = '',
  onClose,
  onHecho,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  onClose: () => void
  onHecho: (a: Notice) => void
}) {
  const [f, setF] = useState<Formulario>(inicial)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setF(inicial())
    setNotice(null)
  }, [open])

  const set = <K extends keyof Formulario>(k: K, value: Formulario[K]) =>
    setF((prev) => ({ ...prev, [k]: value }))

  function cambiarAlgoritmo(algorithm: Algorithm) {
    setF((prev) => ({ ...prev, algorithm, curve: curvaPorDefecto(algorithm) }))
  }

  async function sign() {
    setBusy(true)
    const outcome = await signZone(
      token,
      zone,
      {
        algorithm: f.algorithm,
        hashAlgorithm: f.hashAlgorithm,
        kskKeySize: f.kskKeySize,
        zskKeySize: f.zskKeySize,
        curve: f.curve,
        // The PEMs only make sense with "Use Specified Private Key", but upstream
        // always sends them: if they are empty, they travel empty.
        pemKskPrivateKey: f.kskGeneration === 'UseSpecified' ? f.pemKskPrivateKey : '',
        pemZskPrivateKey: f.zskGeneration === 'UseSpecified' ? f.pemZskPrivateKey : '',
        dnsKeyTtl: f.dnsKeyTtl,
        zskRolloverDays: f.zskRolloverDays,
        nxProof: f.nxProof,
        iterations: f.iterations,
        saltLength: f.saltLength,
      },
      node,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    onHecho({ type: 'success', title: 'Zone Signed!', text: 'The primary zone was signed successfully.' })
  }

  const esRsa = f.algorithm === 'RSA'
  const curvas = f.algorithm === 'EDDSA' ? CURVAS_EDDSA : CURVAS_ECDSA

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={`Sign Zone - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void sign()}>
            Sign Zone
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      <div className={styles.fields}>
        <GroupRow modal label="DNSKEY Algorithm">
          {ALGORITHMS.map((a) => (
            <label key={a.value} className={styles.chk}>
              <input
                type="radio"
                name="signAlgorithm"
                checked={f.algorithm === a.value}
                onChange={() => cambiarAlgoritmo(a.value as Algorithm)}
              />
              {a.label}
            </label>
          ))}
        </GroupRow>

        {esRsa ? (
          <Field label="Hash Algorithm">
            {(id) => (
              <Select id={id} value={f.hashAlgorithm} onChange={(e) => set('hashAlgorithm', e.target.value)}>
                {HASHES_RSA.map((h) => (
                  <option key={h.value} value={h.value}>
                    {h.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <Field label={f.algorithm === 'EDDSA' ? 'EdDSA Curve' : 'ECDSA Curve'}>
            {(id) => (
              <Select id={id} value={f.curve} onChange={(e) => set('curve', e.target.value)}>
                {curvas.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}

        <SigningKey
          title="Key Signing Key (KSK)"
          name="signKsk"
          esRsa={esRsa}
          sizeLabel="KSK Size"
          ayudaTamano="bits (recommended 2048)"
          pemLabel="KSK Private Key"
          generation={f.kskGeneration}
          size={f.kskKeySize}
          pem={f.pemKskPrivateKey}
          onGeneration={(v) => set('kskGeneration', v)}
          onTamano={(v) => set('kskKeySize', v)}
          onPem={(v) => set('pemKskPrivateKey', v)}
        />

        <SigningKey
          title="Zone Signing Key (ZSK)"
          name="signZsk"
          esRsa={esRsa}
          sizeLabel="ZSK Size"
          ayudaTamano="bits (default 1280)"
          pemLabel="ZSK Private Key"
          generation={f.zskGeneration}
          size={f.zskKeySize}
          pem={f.pemZskPrivateKey}
          onGeneration={(v) => set('zskGeneration', v)}
          onTamano={(v) => set('zskKeySize', v)}
          onPem={(v) => set('pemZskPrivateKey', v)}
        />

        <GroupRow modal label="Proof of Non-Existence">
          {PRUEBAS_NX.map((n) => (
            <label key={n.value} className={styles.chk}>
              <input
                type="radio"
                name="signNxProof"
                checked={f.nxProof === n.value}
                onChange={() => set('nxProof', n.value as NxProof)}
              />
              {n.label}
            </label>
          ))}
          <div className={styles.help}>
            With NSEC, all the records in your zone can be discovered by anyone using &quot;zone
            walking&quot; technique. NSEC3 makes it difficult since it uses hashing with a random salt.
          </div>
        </GroupRow>

        {f.nxProof === 'NSEC3' && (
          <>
            <Field label="NSEC3 Iterations">
              {(id) => (
                <div className={styles.inline}>
                  <Input
                    placeholder="iterations"
                    id={id}
                    mono
                    className={styles.short}
                    value={f.iterations}
                    onChange={(e) => set('iterations', e.target.value)}
                  />
                  <span className={styles.suffix}>(valid range 0-50, recommended 0)</span>
                </div>
              )}
            </Field>
            <div className={styles.help}>
              The number of iterations used by NSEC3 for hashing the domain names. It is recommended
              to use 0 iterations since more iterations will increase computational costs for both
              the DNS Server and resolver while not providing much value against &quot;zone
              walking&quot; [<Externo href={RFC_NSEC3_ITERACIONES}>RFC 9276</Externo>].
            </div>
            <Field label="NSEC3 Salt Length">
              {(id) => (
                <div className={styles.inline}>
                  <Input
                    placeholder="length"
                    id={id}
                    mono
                    className={styles.short}
                    value={f.saltLength}
                    onChange={(e) => set('saltLength', e.target.value)}
                  />
                  <span className={styles.suffix}>bytes (valid range 0-32, recommended 0)</span>
                </div>
              )}
            </Field>
            <div className={styles.help}>
              The number of bytes of random salt to generate to be used with the NSEC3 hash
              computation. It is recommended to not use salt by setting the length to 0
              [<Externo href={RFC_NSEC3_SAL}>RFC 9276</Externo>].
            </div>
          </>
        )}

        <Field label="DNSKEY TTL">
          {(id) => (
            <div className={styles.inline}>
              <Input
                placeholder="ttl"
                id={id}
                mono
                className={styles.short}
                value={f.dnsKeyTtl}
                onChange={(e) => set('dnsKeyTtl', e.target.value)}
              />
              <span className={styles.suffix}>seconds (default 3600/1h)</span>
            </div>
          )}
        </Field>
        <div className={styles.help}>
          The TTL value to be used for DNSKEY records. A lower value will allow quicker addition or
          rollover to a new DNS Key at the cost of increased frequency of DNSKEY queries by
          resolvers.
        </div>

        <Field label="ZSK Automatic Rollover">
          {(id) => (
            <div className={styles.inline}>
              <Input
                placeholder="days"
                id={id}
                mono
                className={styles.short}
                value={f.zskRolloverDays}
                onChange={(e) => set('zskRolloverDays', e.target.value)}
              />
              <span className={styles.suffix}>days (valid range 0-365; default 30; set 0 to disable)</span>
            </div>
          )}
        </Field>
        <div className={styles.help}>
          The frequency at which the DNS Server must automatically rollover the Zone Signing Key
          (ZSK).
        </div>

        {/* The link upstream closes `modalDnssecSignZone` with. */}
        <HelpText href={AYUDA_DNSSEC}>Help: How To Secure Your Domain Name With DNSSEC</HelpText>
      </div>
    </Dialog>
  )
}

/** KSK and ZSK are the same block with different labels and defaults. */
function SigningKey({
  title,
  name,
  esRsa,
  sizeLabel,
  ayudaTamano,
  pemLabel,
  generation,
  size,
  pem,
  onGeneration,
  onTamano,
  onPem,
}: {
  title: string
  name: string
  esRsa: boolean
  sizeLabel: string
  ayudaTamano: string
  pemLabel: string
  generation: string
  size: string
  pem: string
  onGeneration: (v: string) => void
  onTamano: (v: string) => void
  onPem: (v: string) => void
}) {
  return (
    <div className={styles.group}>
      <div className={styles.groupTitle}>{title}</div>
      {GENERACIONES.map((g) => (
        <label key={g.value} className={styles.chk}>
          <input
            type="radio"
            name={name}
            checked={generation === g.value}
            onChange={() => onGeneration(g.value)}
          />
          {g.label}
        </label>
      ))}

      {/* The size only applies to RSA and only with automatic generation. */}
      {esRsa && generation === 'Automatic' && (
        <Field label={sizeLabel}>
          {(id) => (
            <div className={styles.inline}>
              <Select id={id} className={styles.short} value={size} onChange={(e) => onTamano(e.target.value)}>
                {TAMANOS_RSA.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
              <span className={styles.suffix}>{ayudaTamano}</span>
            </div>
          )}
        </Field>
      )}

      {generation === 'UseSpecified' && (
        <Field label={pemLabel}>
          {(id) => (
            <Textarea
              id={id}
              mono
              className={styles.area}
              spellCheck={false}
              value={pem}
              onChange={(e) => onPem(e.target.value)}
            />
          )}
        </Field>
      )}
      {generation === 'UseSpecified' && (
        <div className={styles.help}>Enter a private key in PEM format.</div>
      )}
    </div>
  )
}
