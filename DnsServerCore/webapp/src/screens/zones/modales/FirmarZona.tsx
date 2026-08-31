import { useEffect, useState } from 'react'
import { signZone, type Algoritmo, type NxProof } from '../../../api/dnssec'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import {
  ALGORITMOS,
  CURVAS_ECDSA,
  CURVAS_EDDSA,
  GENERACIONES,
  HASHES_RSA,
  PRUEBAS_NX,
  TAMANOS_RSA,
  curvaPorDefecto,
} from './dnssec-opciones'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'
import { Ayuda, Externo } from '../../../ui/Externo'
import { AYUDA_DNSSEC, RFC_NSEC3_ITERACIONES, RFC_NSEC3_SAL } from '../referencias'
import { GroupRow } from '../../../ui/Form'
import { avisoDeFallo } from '../../../lib/aviso'

/*
`modalDnssecSignZone` (zone.js:6539 y 6578).

Los valores iniciales NO son los de un formulario vacío: ECDSA con P256, KSK y
ZSK automáticas, NSEC, TTL 3600 y rollover del ZSK cada 30 días. Y los tamaños
por defecto de RSA son **distintos entre KSK y ZSK** —2048 y 1280—, que es la
clase de detalle que se pierde al «limpiar» un formulario.
*/

interface Formulario {
  algorithm: Algoritmo
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

export function FirmarZona({
  zone,
  abierto,
  token,
  node = '',
  onCerrar,
  onHecho,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const [f, setF] = useState<Formulario>(inicial)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setF(inicial())
    setAviso(null)
  }, [abierto])

  const set = <K extends keyof Formulario>(k: K, valor: Formulario[K]) =>
    setF((prev) => ({ ...prev, [k]: valor }))

  function cambiarAlgoritmo(algorithm: Algoritmo) {
    setF((prev) => ({ ...prev, algorithm, curve: curvaPorDefecto(algorithm) }))
  }

  async function firmar() {
    setOcupado(true)
    const outcome = await signZone(
      token,
      zone,
      {
        algorithm: f.algorithm,
        hashAlgorithm: f.hashAlgorithm,
        kskKeySize: f.kskKeySize,
        zskKeySize: f.zskKeySize,
        curve: f.curve,
        // Los PEM sólo tienen sentido con «Use Specified Private Key», pero
        // upstream los manda siempre: si están vacíos, viajan vacíos.
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
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Zone Signed!', text: 'The primary zone was signed successfully.' })
  }

  const esRsa = f.algorithm === 'RSA'
  const curvas = f.algorithm === 'EDDSA' ? CURVAS_EDDSA : CURVAS_ECDSA

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={`Sign Zone - ${zone === '.' ? '<root>' : zone}`}
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void firmar()}>
            Sign Zone
          </Button>
        </>
      }
    >
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

      <div className={styles.campos}>
        <GroupRow modal label="DNSKEY Algorithm">
          {ALGORITMOS.map((a) => (
            <label key={a.valor} className={styles.chk}>
              <input
                type="radio"
                name="signAlgorithm"
                checked={f.algorithm === a.valor}
                onChange={() => cambiarAlgoritmo(a.valor as Algoritmo)}
              />
              {a.etiqueta}
            </label>
          ))}
        </GroupRow>

        {esRsa ? (
          <Field label="Hash Algorithm">
            {(id) => (
              <Select id={id} value={f.hashAlgorithm} onChange={(e) => set('hashAlgorithm', e.target.value)}>
                {HASHES_RSA.map((h) => (
                  <option key={h.valor} value={h.valor}>
                    {h.etiqueta}
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
                  <option key={c.valor} value={c.valor}>
                    {c.etiqueta}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}

        <ClaveDeFirma
          titulo="Key Signing Key (KSK)"
          nombre="signKsk"
          esRsa={esRsa}
          etiquetaTamano="KSK Size"
          ayudaTamano="bits (recommended 2048)"
          etiquetaPem="KSK Private Key"
          generacion={f.kskGeneration}
          tamano={f.kskKeySize}
          pem={f.pemKskPrivateKey}
          onGeneracion={(v) => set('kskGeneration', v)}
          onTamano={(v) => set('kskKeySize', v)}
          onPem={(v) => set('pemKskPrivateKey', v)}
        />

        <ClaveDeFirma
          titulo="Zone Signing Key (ZSK)"
          nombre="signZsk"
          esRsa={esRsa}
          etiquetaTamano="ZSK Size"
          ayudaTamano="bits (default 1280)"
          etiquetaPem="ZSK Private Key"
          generacion={f.zskGeneration}
          tamano={f.zskKeySize}
          pem={f.pemZskPrivateKey}
          onGeneracion={(v) => set('zskGeneration', v)}
          onTamano={(v) => set('zskKeySize', v)}
          onPem={(v) => set('pemZskPrivateKey', v)}
        />

        <GroupRow modal label="Proof of Non-Existence">
          {PRUEBAS_NX.map((n) => (
            <label key={n.valor} className={styles.chk}>
              <input
                type="radio"
                name="signNxProof"
                checked={f.nxProof === n.valor}
                onChange={() => set('nxProof', n.valor as NxProof)}
              />
              {n.etiqueta}
            </label>
          ))}
          <div className={styles.ayuda}>
            With NSEC, all the records in your zone can be discovered by anyone using &quot;zone
            walking&quot; technique. NSEC3 makes it difficult since it uses hashing with a random salt.
          </div>
        </GroupRow>

        {f.nxProof === 'NSEC3' && (
          <>
            <Field label="NSEC3 Iterations">
              {(id) => (
                <div className={styles.enLinea}>
                  <Input
                    id={id}
                    mono
                    className={styles.corto}
                    value={f.iterations}
                    onChange={(e) => set('iterations', e.target.value)}
                  />
                  <span className={styles.sufijo}>(valid range 0-50, recommended 0)</span>
                </div>
              )}
            </Field>
            <div className={styles.ayuda}>
              The number of iterations used by NSEC3 for hashing the domain names. It is recommended
              to use 0 iterations since more iterations will increase computational costs for both
              the DNS Server and resolver while not providing much value against &quot;zone
              walking&quot; [<Externo href={RFC_NSEC3_ITERACIONES}>RFC 9276</Externo>].
            </div>
            <Field label="NSEC3 Salt Length">
              {(id) => (
                <div className={styles.enLinea}>
                  <Input
                    id={id}
                    mono
                    className={styles.corto}
                    value={f.saltLength}
                    onChange={(e) => set('saltLength', e.target.value)}
                  />
                  <span className={styles.sufijo}>bytes (valid range 0-32, recommended 0)</span>
                </div>
              )}
            </Field>
            <div className={styles.ayuda}>
              The number of bytes of random salt to generate to be used with the NSEC3 hash
              computation. It is recommended to not use salt by setting the length to 0
              [<Externo href={RFC_NSEC3_SAL}>RFC 9276</Externo>].
            </div>
          </>
        )}

        <Field label="DNSKEY TTL">
          {(id) => (
            <div className={styles.enLinea}>
              <Input
                id={id}
                mono
                className={styles.corto}
                value={f.dnsKeyTtl}
                onChange={(e) => set('dnsKeyTtl', e.target.value)}
              />
              <span className={styles.sufijo}>seconds (default 3600/1h)</span>
            </div>
          )}
        </Field>
        <div className={styles.ayuda}>
          The TTL value to be used for DNSKEY records. A lower value will allow quicker addition or
          rollover to a new DNS Key at the cost of increased frequency of DNSKEY queries by
          resolvers.
        </div>

        <Field label="ZSK Automatic Rollover">
          {(id) => (
            <div className={styles.enLinea}>
              <Input
                id={id}
                mono
                className={styles.corto}
                value={f.zskRolloverDays}
                onChange={(e) => set('zskRolloverDays', e.target.value)}
              />
              <span className={styles.sufijo}>days (valid range 0-365; default 30; set 0 to disable)</span>
            </div>
          )}
        </Field>
        <div className={styles.ayuda}>
          The frequency at which the DNS Server must automatically rollover the Zone Signing Key
          (ZSK).
        </div>

        {/* El enlace con el que upstream cierra `modalDnssecSignZone`. */}
        <Ayuda href={AYUDA_DNSSEC}>Help: How To Secure Your Domain Name With DNSSEC</Ayuda>
      </div>
    </Dialog>
  )
}

/** KSK y ZSK son el mismo bloque con distintos rótulos y valores por defecto. */
function ClaveDeFirma({
  titulo,
  nombre,
  esRsa,
  etiquetaTamano,
  ayudaTamano,
  etiquetaPem,
  generacion,
  tamano,
  pem,
  onGeneracion,
  onTamano,
  onPem,
}: {
  titulo: string
  nombre: string
  esRsa: boolean
  etiquetaTamano: string
  ayudaTamano: string
  etiquetaPem: string
  generacion: string
  tamano: string
  pem: string
  onGeneracion: (v: string) => void
  onTamano: (v: string) => void
  onPem: (v: string) => void
}) {
  return (
    <div className={styles.grupo}>
      <div className={styles.grupoTit}>{titulo}</div>
      {GENERACIONES.map((g) => (
        <label key={g.valor} className={styles.chk}>
          <input
            type="radio"
            name={nombre}
            checked={generacion === g.valor}
            onChange={() => onGeneracion(g.valor)}
          />
          {g.etiqueta}
        </label>
      ))}

      {/* El tamaño sólo aplica a RSA y sólo con generación automática. */}
      {esRsa && generacion === 'Automatic' && (
        <Field label={etiquetaTamano}>
          {(id) => (
            <div className={styles.enLinea}>
              <Select id={id} className={styles.corto} value={tamano} onChange={(e) => onTamano(e.target.value)}>
                {TAMANOS_RSA.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
              <span className={styles.sufijo}>{ayudaTamano}</span>
            </div>
          )}
        </Field>
      )}

      {generacion === 'UseSpecified' && (
        <Field label={etiquetaPem}>
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
      {generacion === 'UseSpecified' && (
        <div className={styles.ayuda}>Enter a private key in PEM format.</div>
      )}
    </div>
  )
}
