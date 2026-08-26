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
      setAviso({
        type: 'danger',
        title: 'Error!',
        text: outcome.kind === 'error' ? outcome.message : 'Invalid token or session expired.',
      })
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
      title="Add Zone"
      footer={
        <>
          <Button onClick={onCerrar}>Close</Button>
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

        <div className={styles.fila}>
          <div className={styles.filaLab}>Zone Type</div>
          <div className={styles.filaCtl}>
            {TIPOS_ALTA.map((t) => (
              <label key={t.valor} className={styles.chk}>
                <input
                  type="radio"
                  name="addZoneType"
                  checked={f.tipo === t.valor}
                  onChange={() => cambiarTipo(t.valor)}
                />
                {t.etiqueta}
              </label>
            ))}
          </div>
        </div>

        {v.catalogo && catalogos.length > 0 && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>
              <label htmlFor="addZoneCatalog">Catalog Zone</label>
            </div>
            <div className={styles.filaCtl}>
              <Select id="addZoneCatalog" value={f.catalog} onChange={(e) => set('catalog', e.target.value)}>
                <option value="" />
                {catalogos.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
              <div className={styles.ayuda}>
                Select a Catalog zone to register as its member zone.
              </div>
            </div>
          </div>
        )}

        {v.casillaInicializarForwarder && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>Conditional Forwarder</div>
            <div className={styles.filaCtl}>
              <label className={styles.chk}>
                <input
                  type="checkbox"
                  checked={f.initializeForwarder}
                  onChange={(e) => set('initializeForwarder', e.target.checked)}
                />
                Initialize Forwarder (FWD) Record
              </label>
            </div>
          </div>
        )}

        {v.ficheroDeZona && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>
              <label htmlFor="addZoneFile">Import Zone File (Optional)</label>
            </div>
            <div className={styles.filaCtl}>
              <input
                id="addZoneFile"
                type="file"
                onChange={(e) => setArchivo(e.target.files?.[0] ?? null)}
              />
            </div>
          </div>
        )}

        {v.serieSoa && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>Zone Serial</div>
            <div className={styles.filaCtl}>
              <label className={styles.chk}>
                <input
                  type="checkbox"
                  checked={f.useSoaSerialDateScheme}
                  onChange={(e) => set('useSoaSerialDateScheme', e.target.checked)}
                />
                Use SOA Serial Date Scheme
              </label>
            </div>
          </div>
        )}

        {v.servidoresPrimarios && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>
              <label htmlFor="addZonePrimaries">
                {v.servidoresPrimariosObligatorios
                  ? 'Primary Name Server Addresses'
                  : 'Primary Name Server Addresses (Optional)'}
              </label>
            </div>
            <div className={styles.filaCtl}>
              <Textarea
                id="addZonePrimaries"
                mono
                className={styles.area}
                spellCheck={false}
                value={f.primaryNameServerAddresses}
                onChange={(e) => set('primaryNameServerAddresses', e.target.value)}
              />
              <div className={styles.ayuda}>
                {v.servidoresPrimariosObligatorios
                  ? 'Enter the primary name server addresses to sync the zone from.'
                  : 'Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.'}
              </div>
            </div>
          </div>
        )}

        {v.protocoloTransferencia && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>Zone Transfer Protocol</div>
            <div className={styles.filaCtl}>
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
            </div>
          </div>
        )}

        {v.tsig && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>
              <label htmlFor="addZoneTsig">TSIG Key Name (Optional)</label>
            </div>
            <div className={styles.filaCtl}>
              <Select id="addZoneTsig" value={f.tsigKeyName} onChange={(e) => set('tsigKeyName', e.target.value)}>
                <option value="" />
                {tsigKeys.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
            </div>
          </div>
        )}

        {v.validarZona && (
          <div className={styles.fila}>
            <div className={styles.filaLab}>Zone Validation</div>
            <div className={styles.filaCtl}>
              <label className={styles.chk}>
                <input
                  type="checkbox"
                  checked={f.validateZone}
                  onChange={(e) => set('validateZone', e.target.checked)}
                />
                Use ZONEMD to Validate Zone
              </label>
              <div className={styles.ayuda}>
                When enabled, the secondary zone will be validated using the ZONEMD record after every
                zone transfer. The zone will get disabled if the validation fails. The zone must be DNSSEC
                signed for the validation to work.
              </div>
            </div>
          </div>
        )}

        {v.camposDeForwarder && (
          <>
            <div className={styles.fila}>
              <div className={styles.filaLab}>Protocol</div>
              <div className={styles.filaCtl}>
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
              </div>
            </div>

            <div className={styles.fila}>
              <div className={styles.filaLab}>
                <label htmlFor="addZoneForwarder">Forwarder</label>
              </div>
              <div className={styles.filaCtl}>
                <Input
                  id="addZoneForwarder"
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
                <div className={styles.ayuda}>
                  When using &quot;This Server&quot;, if a record does not exists in the zone then the
                  request is forwarded to the DNS Server&apos;s resolver internally. This allows you to
                  override any record for the forwarded domain name or control its DNSSEC validation.
                </div>
                <div className={styles.ayuda}>
                  Enter a forwarder server address above. You can add more forwarders by adding FWD records
                  after the zone is added.
                </div>
              </div>
            </div>

            <div className={styles.fila}>
              <div className={styles.filaLab}>DNSSEC</div>
              <div className={styles.filaCtl}>
                <label className={styles.chk}>
                  <input
                    type="checkbox"
                    checked={f.dnssecValidation}
                    onChange={(e) => set('dnssecValidation', e.target.checked)}
                  />
                  Enable DNSSEC Validation
                </label>
              </div>
            </div>

            {/* «this-server» no admite proxy: upstream esconde el bloque entero. */}
            {!f.usarEsteServidor && (
              <div className={styles.fila}>
                <div className={styles.filaLab}>Network Proxy</div>
                <div className={styles.filaCtl}>
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
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Dialog>
  )
}
