import { useEffect, useRef, useState } from 'react'
import { createZone, listCatalogs } from '../../../api/zones'
import { getTsigKeyNames } from '../../../api/settings'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'
import {
  admiteFicheroDeZona,
  construirParametrosAlta,
  ejemploDeForwarder,
  formularioAltaInicial,
  proxyEditable,
  PROTOCOLOS_FORWARDER,
  PROTOCOLOS_TRANSFERENCIA,
  seccionesVisibles,
  TIPOS_ALTA,
  TIPOS_PROXY,
  type FormularioAlta,
  type TipoAlta,
} from './anadir-zona'
import { Ayuda, Externo } from '../../../ui/Externo'
import { RFC_ZONEMD } from '../referencias'
import { GroupRow, Row } from '../../../ui/Form'
import { avisoDeFallo } from '../../../lib/aviso'

/*
`modalAddZone` (zone.js:2726 y 2911). Ocho tipos de zona, cada uno con su
formulario. La decisión de qué se ve y qué viaja está en `anadir-zona.ts`, que
se prueba sin montar nada.

El catálogo sólo se ofrece **si el servidor devolvió alguno**: upstream marca el
desplegable con `hasItems` y las ramas del `switch` lo comprueban antes de
mostrarlo. Un servidor sin zonas de catálogo no enseña ese campo en absoluto.
*/

export function AnadirZona({
  abierto,
  token,
  node = '',
  useSoaSerialDateScheme,
  dnssecValidation,
  onCerrar,
  onCreada,
}: {
  abierto: boolean
  token: string | null
  node?: string
  /** Ambos heredan del ajuste global de Settings, no de `false`. */
  useSoaSerialDateScheme: boolean
  dnssecValidation: boolean
  onCerrar: () => void
  onCreada: (domain: string, aviso: Aviso) => void
}) {
  const [f, setF] = useState<FormularioAlta>(() =>
    formularioAltaInicial(useSoaSerialDateScheme, dnssecValidation),
  )
  const [catalogos, setCatalogos] = useState<string[]>([])
  const [tsigKeys, setTsigKeys] = useState<string[]>([])
  const [archivo, setArchivo] = useState<File | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const zonaRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!abierto) return
    setF(formularioAltaInicial(useSoaSerialDateScheme, dnssecValidation))
    setArchivo(null)
    setAviso(null)
    void listCatalogs(token, node).then((c) => setCatalogos(c ?? []))
    void getTsigKeyNames(token, node).then(setTsigKeys)
    zonaRef.current?.focus()
  }, [abierto, token, node, useSoaSerialDateScheme, dnssecValidation])

  const v = seccionesVisibles(f.tipo, f.initializeForwarder)
  const set = <K extends keyof FormularioAlta>(k: K, valor: FormularioAlta[K]) =>
    setF((prev) => ({ ...prev, [k]: valor }))

  function cambiarTipo(tipo: TipoAlta) {
    const secciones = seccionesVisibles(tipo, f.initializeForwarder)
    setF((prev) => ({ ...prev, tipo, zone: secciones.zonaFija ?? prev.zone }))
  }

  async function crear() {
    const r = construirParametrosAlta(f)
    if ('error' in r) {
      setAviso({ type: 'warning', title: r.error.title, text: r.error.text })
      if (r.error.campo === 'zone') zonaRef.current?.focus()
      return
    }

    setOcupado(true)
    const outcome = await createZone(
      token,
      r.parametros,
      admiteFicheroDeZona(f.tipo) ? archivo : null,
      node,
    )
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    onCerrar()
    // Upstream abre la zona recién creada, no vuelve a la lista.
    onCreada(outcome.data.response.domain, {
      type: 'success',
      title: 'Zone Added!',
      text: 'Zone was added successfully.',
    })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      tamano="medio"
      title="Add Zone"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void crear()}>
            Add
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
        <Field label="Zone">
          {(id) => (
            <Input
              id={id}
              mono
              ref={zonaRef}
              disabled={v.zonaFija != null}
              value={f.zone}
              onChange={(e) => set('zone', e.target.value)}
            />
          )}
        </Field>

        <GroupRow modal label="Zone Type">
          {TIPOS_ALTA.map((t) => (
            <label key={t.valor} className={styles.chk}>
              <input
                type="radio"
                name="addZoneType"
                checked={f.tipo === t.valor}
                onChange={() => cambiarTipo(t.valor)}
              />
              {/*
              `.chk` es `display:flex`, así que cada hijo del rótulo es un
              ítem: sin este `span` el enlace y los paréntesis se separaban en
              tres cajas —«Secondary ROOT Zone ( RFC 8806 )»— y el enlace
              dejaba de estar dentro de una frase, que es lo que le da la
              excepción de tamaño de objetivo. Envuelto, vuelve a ser texto.
              */}
              <span>
                {t.etiqueta}
                {t.referencia && (
                  <>
                    {' ('}
                    <Externo href={t.referencia.href}>{t.referencia.texto}</Externo>
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

        {v.ficheroDeZona && (
          <Row modal label="Import Zone File (Optional)">
            {(id) => (
              <input
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

        {v.protocoloTransferencia && (
          <GroupRow modal label="Zone Transfer Protocol">
            {PROTOCOLOS_TRANSFERENCIA.map((p) => (
              <label key={p.valor} className={styles.chk}>
                <input
                  type="radio"
                  name="addZoneTransferProtocol"
                  checked={f.zoneTransferProtocol === p.valor}
                  onChange={() => set('zoneTransferProtocol', p.valor)}
                />
                {p.etiqueta}
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

        {v.validarZona && (
          <GroupRow modal label="Zone Validation">
            <label className={styles.chk}>
              <input
                type="checkbox"
                checked={f.validateZone}
                onChange={(e) => set('validateZone', e.target.checked)}
              />
              Use <Externo href={RFC_ZONEMD}>ZONEMD</Externo> to Validate Zone
            </label>
            <div className={styles.ayuda}>
              When enabled, the secondary zone will be validated using the ZONEMD record after every
              zone transfer. The zone will get disabled if the validation fails. The zone must be DNSSEC
              signed for the validation to work.
            </div>
          </GroupRow>
        )}

        {v.camposDeForwarder && (
          <>
            <GroupRow modal label="Protocol">
              {PROTOCOLOS_FORWARDER.map((p) => (
                <label key={p.valor} className={styles.chk}>
                  <input
                    type="radio"
                    name="addZoneForwarderProtocol"
                    disabled={f.usarEsteServidor}
                    checked={f.forwarderProtocol === p.valor}
                    onChange={() => set('forwarderProtocol', p.valor)}
                  />
                  {p.etiqueta}
                </label>
              ))}
            </GroupRow>

            {/* Dos párrafos de ayuda: los dos de upstream, uno sobre «This Server» y
                otro sobre añadir más reenviadores después. */}
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

            {/* «this-server» no admite proxy: upstream esconde el bloque entero. */}
            {!f.usarEsteServidor && (
              <GroupRow modal label="Network Proxy">
                {TIPOS_PROXY.map((p) => (
                  <label key={p.valor} className={styles.chk}>
                    <input
                      type="radio"
                      name="addZoneProxyType"
                      checked={f.proxyType === p.valor}
                      onChange={() => set('proxyType', p.valor)}
                    />
                    {p.etiqueta}
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
            )}
          </>
        )}

        {/* Upstream cierra este diálogo con su enlace de ayuda (`modalAddZone`). */}
        <Ayuda href="https://blog.technitium.com/2022/06/how-to-self-host-your-own-domain-name.html">
          Help: How To Self Host Your Own Domain Name
        </Ayuda>
      </div>
    </Dialog>
  )
}
