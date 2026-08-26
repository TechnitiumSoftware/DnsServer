import { useEffect, useState } from 'react'
import { getZoneOptions, setZoneOptions, type OpcionesZona as Respuesta } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Input, Select, Textarea } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import {
  ACCESOS_CONSULTA,
  ACTUALIZACIONES,
  NOTIFICACIONES,
  PESTANAS,
  PROTOCOLOS_XFR,
  TRANSFERENCIAS,
  aclEditable,
  construirCuerpoOpciones,
  estadoOpciones,
  formularioDesdeOpciones,
  notificacionConLista,
  type EstadoOpciones,
  type FormularioOpciones,
  type PestanaOpciones,
} from '../opciones'
import type { Aviso } from '../tipos'
import styles from '../Zones.module.css'

/*
`modalZoneOptions` (zone.js:1524 y 2380). Cinco pestañas y una matriz de
visibilidad que decide `opciones.ts`.

**El formulario es UNO SOLO**: «Save» manda los campos de las cinco pestañas
estés donde estés, igual que en Settings. Trocearlo por pestaña cambiaría lo
que se guarda.

Y por eso mismo, si la validación falla en una pestaña que no está delante, se
salta a ella: es la misma desviación deliberada que se decidió en Settings, y
por la misma razón — con un panel montado a la vez, sin el salto el aviso sería
imposible de resolver.
*/

export function OpcionesZona({
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
  const [respuesta, setRespuesta] = useState<Respuesta | null>(null)
  const [f, setF] = useState<FormularioOpciones | null>(null)
  const [pestana, setPestana] = useState<PestanaOpciones>('General')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cargando, setCargando] = useState(false)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setCargando(true)
    void getZoneOptions(token, zone, node).then((r) => {
      setCargando(false)
      if (r == null) {
        setAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setRespuesta(r)
      setF(formularioDesdeOpciones(r))
      setPestana(estadoOpciones(r).pestanaInicial)
    })
  }, [abierto, token, zone, node])

  const e: EstadoOpciones | null = respuesta ? estadoOpciones(respuesta) : null

  const set = <K extends keyof FormularioOpciones>(k: K, valor: FormularioOpciones[K]) =>
    setF((prev) => (prev == null ? prev : { ...prev, [k]: valor }))

  async function guardar() {
    if (f == null || respuesta == null) return

    const r = construirCuerpoOpciones(f, respuesta.type)
    if ('error' in r) {
      setPestana(r.error.tab)
      setAviso({ type: 'warning', title: r.error.title, text: r.error.text })
      return
    }

    setOcupado(true)
    const outcome = await setZoneOptions(token, { zone, ...r.body }, node)
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
    onHecho({ type: 'success', title: 'Options Saved!', text: 'Zone options were saved successfully.' })
  }

  const tsigDisponibles = respuesta?.availableTsigKeyNames ?? []
  const catalogosDisponibles = respuesta?.availableCatalogZoneNames ?? []

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      ancho
      title={`Zone Options - ${zone === '.' ? '<root>' : zone}`}
      acciones={
        <>
          <Button variant="primary" disabled={ocupado || f == null} onClick={() => void guardar()}>
            Save
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

      {cargando || f == null || e == null ? (
        <Loading>Loading zone options…</Loading>
      ) : (
        <>
          <div className={styles.filt} role="tablist">
            {PESTANAS.filter((t) => e.pestanas.includes(t.id)).map((t) => (
              <button
                key={t.id}
                type="button"
                role="tab"
                className={styles.pgBtn}
                aria-selected={pestana === t.id}
                aria-current={pestana === t.id}
                onClick={() => setPestana(t.id)}
              >
                {t.etiqueta}
              </button>
            ))}
          </div>

          <div className={styles.campos}>
            {pestana === 'General' && (
              <>
                {e.catalogo && (
                  <>
                    <Field label="Catalog Zone">
                      {(id) => (
                        <Select
                          id={id}
                          disabled={e.catalogoFijo}
                          value={f.catalog}
                          onChange={(ev) => set('catalog', ev.target.value)}
                        >
                          <option value="" />
                          {(e.catalogoFijo && f.catalog !== ''
                            ? [f.catalog]
                            : catalogosDisponibles
                          ).map((c) => (
                            <option key={c} value={c}>
                              {c}
                            </option>
                          ))}
                        </Select>
                      )}
                    </Field>

                    {e.sobrescribirQueryAccess && (
                      <label className={styles.chk}>
                        <input
                          type="checkbox"
                          disabled={e.sobrescribirBloqueado}
                          checked={f.overrideCatalogQueryAccess}
                          onChange={(ev) => set('overrideCatalogQueryAccess', ev.target.checked)}
                        />
                        Override Query Access Option
                      </label>
                    )}
                    {e.sobrescribirZoneTransfer && (
                      <label className={styles.chk}>
                        <input
                          type="checkbox"
                          disabled={e.sobrescribirBloqueado}
                          checked={f.overrideCatalogZoneTransfer}
                          onChange={(ev) => set('overrideCatalogZoneTransfer', ev.target.checked)}
                        />
                        Override Zone Transfer Option
                      </label>
                    )}
                    {e.sobrescribirNotify && (
                      <label className={styles.chk}>
                        <input
                          type="checkbox"
                          disabled={e.sobrescribirBloqueado}
                          checked={f.overrideCatalogNotify}
                          onChange={(ev) => set('overrideCatalogNotify', ev.target.checked)}
                        />
                        Override Notify Option
                      </label>
                    )}
                  </>
                )}

                {e.servidorPrimario && (
                  <>
                    <Field
                      label={
                        e.servidorPrimarioObligatorio
                          ? 'Primary Name Server Addresses'
                          : 'Primary Name Server Addresses (Optional)'
                      }
                    >
                      {(id) => (
                        <Textarea
                          id={id}
                          mono
                          className={styles.area}
                          disabled={e.servidorPrimarioBloqueado}
                          value={f.primaryNameServerAddresses}
                          onChange={(ev) => set('primaryNameServerAddresses', ev.target.value)}
                        />
                      )}
                    </Field>
                    <div className={styles.ayuda}>
                      {e.servidorPrimarioObligatorio
                        ? 'Enter the primary name server addresses to sync the zone from.'
                        : 'Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.'}
                    </div>

                    {e.protocoloXfr && (
                      <div className={styles.fila}>
                        <div className={styles.filaLab}>Zone Transfer Protocol</div>
                        <div className={styles.filaCtl}>
                          {PROTOCOLOS_XFR.map((x) => (
                            <label key={x.valor} className={styles.chk}>
                              <input
                                type="radio"
                                name="zoneOptionsXfr"
                                disabled={e.servidorPrimarioBloqueado}
                                checked={f.primaryZoneTransferProtocol === x.valor}
                                onChange={() => set('primaryZoneTransferProtocol', x.valor)}
                              />
                              {x.etiqueta}
                            </label>
                          ))}
                        </div>
                      </div>
                    )}

                    {e.tsigDelPrimario && (
                      <Field label="TSIG Key Name (Optional)">
                        {(id) => (
                          <Select
                            id={id}
                            disabled={e.servidorPrimarioBloqueado}
                            value={f.primaryZoneTransferTsigKeyName}
                            onChange={(ev) => set('primaryZoneTransferTsigKeyName', ev.target.value)}
                          >
                            <option value="" />
                            {tsigDisponibles.map((k) => (
                              <option key={k} value={k}>
                                {k}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                    )}

                    {e.validarZona && (
                      <label className={styles.chk}>
                        <input
                          type="checkbox"
                          disabled={e.servidorPrimarioBloqueado}
                          checked={f.validateZone}
                          onChange={(ev) => set('validateZone', ev.target.checked)}
                        />
                        Use ZONEMD to Validate Zone
                      </label>
                    )}
                  </>
                )}
              </>
            )}

            {pestana === 'Query Access' && (
              <Criterio
                nombre="zoneOptionsQueryAccess"
                opciones={ACCESOS_CONSULTA.filter(
                  (o) => e.queryAccessConNameServers || !o.valor.includes('ZoneNameServers'),
                )}
                valor={f.queryAccess}
                bloqueado={e.queryAccessBloqueado}
                onCambio={(v) => set('queryAccess', v)}
                lista={f.queryAccessNetworkACL}
                listaEtiqueta="Network Access Control List (ACL)"
                listaEditable={aclEditable(f.queryAccess) && !e.queryAccessBloqueado}
                onLista={(v) => set('queryAccessNetworkACL', v)}
              />
            )}

            {pestana === 'Zone Transfer' && (
              <>
                <Criterio
                  nombre="zoneOptionsZoneTransfer"
                  opciones={TRANSFERENCIAS.filter(
                    (o) => e.zoneTransferConNameServers || !o.valor.includes('ZoneNameServers'),
                  )}
                  valor={f.zoneTransfer}
                  bloqueado={e.zoneTransferBloqueado}
                  onCambio={(v) => set('zoneTransfer', v)}
                  lista={f.zoneTransferNetworkACL}
                  listaEtiqueta="Network Access Control List (ACL)"
                  listaEditable={aclEditable(f.zoneTransfer) && !e.zoneTransferBloqueado}
                  onLista={(v) => set('zoneTransferNetworkACL', v)}
                />
                <Field label="Zone Transfer TSIG Key Names">
                  {(id) => (
                    <Textarea
                      id={id}
                      mono
                      className={styles.area}
                      disabled={e.zoneTransferBloqueado}
                      value={f.zoneTransferTsigKeyNames}
                      onChange={(ev) => set('zoneTransferTsigKeyNames', ev.target.value)}
                    />
                  )}
                </Field>
                {/* «Quick Add» sólo añade a la lista de arriba: no manda nada. */}
                <Field label="Quick Add">
                  {(id) => (
                    <Select
                      id={id}
                      disabled={e.zoneTransferBloqueado}
                      value=""
                      onChange={(ev) => {
                        const v = ev.target.value
                        if (v === '') return
                        const actual = f.zoneTransferTsigKeyNames
                        set('zoneTransferTsigKeyNames', actual === '' ? v : `${actual}\n${v}`)
                      }}
                    >
                      <option value="" />
                      <option value="none">None</option>
                      {tsigDisponibles.map((k) => (
                        <option key={k} value={k}>
                          {k}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              </>
            )}

            {pestana === 'Notify' && (
              <>
                <Criterio
                  nombre="zoneOptionsNotify"
                  opciones={NOTIFICACIONES.filter((o) => {
                    if (o.valor === 'SeparateNameServersForCatalogAndMemberZones') return e.notifySeparados
                    if (o.valor === 'ZoneNameServers' || o.valor === 'BothZoneAndSpecifiedNameServers') {
                      return e.notifyConNameServers
                    }
                    return true
                  })}
                  valor={f.notify}
                  bloqueado={false}
                  onCambio={(v) => set('notify', v)}
                  lista={f.notifyNameServers}
                  listaEtiqueta="Specified Name Servers"
                  listaEditable={notificacionConLista(f.notify)}
                  onLista={(v) => set('notifyNameServers', v)}
                />
                {e.notifySeparados && (
                  <Field label="Secondary Catalog Name Servers">
                    {(id) => (
                      <Textarea
                        id={id}
                        mono
                        className={styles.area}
                        disabled={f.notify !== 'SeparateNameServersForCatalogAndMemberZones'}
                        value={f.notifySecondaryCatalogsNameServers}
                        onChange={(ev) => set('notifySecondaryCatalogsNameServers', ev.target.value)}
                      />
                    )}
                  </Field>
                )}
                {respuesta?.notifyFailed === true && (
                  <div className={`${styles.nota} ${styles.notaAviso}`}>
                    <b>Notify Failed For:</b> {(respuesta.notifyFailedFor ?? []).join(', ')}
                  </div>
                )}
              </>
            )}

            {pestana === 'Dynamic Updates' && (
              <>
                <Criterio
                  nombre="zoneOptionsUpdate"
                  opciones={ACTUALIZACIONES.filter(
                    (o) => e.updateConNameServers || !o.valor.includes('ZoneNameServers'),
                  )}
                  valor={f.update}
                  bloqueado={false}
                  onCambio={(v) => set('update', v)}
                  lista={f.updateNetworkACL}
                  listaEtiqueta="Network Access Control List (ACL)"
                  listaEditable={aclEditable(f.update)}
                  onLista={(v) => set('updateNetworkACL', v)}
                />

                {e.politicasDeSeguridad && (
                  <div className={styles.grupo}>
                    <div className={styles.grupoTit}>Security Policy</div>
                    {f.updateSecurityPolicies.map((fila, i) => (
                      <div key={i} className={styles.enLinea}>
                        <Select
                          aria-label={`TSIG key name ${i + 1}`}
                          value={fila.tsigKeyName}
                          onChange={(ev) =>
                            set(
                              'updateSecurityPolicies',
                              f.updateSecurityPolicies.map((x, j) =>
                                j === i ? { ...x, tsigKeyName: ev.target.value } : x,
                              ),
                            )
                          }
                        >
                          <option value="" />
                          {tsigDisponibles.map((k) => (
                            <option key={k} value={k}>
                              {k}
                            </option>
                          ))}
                        </Select>
                        <Input
                          mono
                          aria-label={`Domain ${i + 1}`}
                          value={fila.domain}
                          onChange={(ev) =>
                            set(
                              'updateSecurityPolicies',
                              f.updateSecurityPolicies.map((x, j) =>
                                j === i ? { ...x, domain: ev.target.value } : x,
                              ),
                            )
                          }
                        />
                        <Input
                          mono
                          aria-label={`Allowed types ${i + 1}`}
                          value={fila.allowedTypes}
                          onChange={(ev) =>
                            set(
                              'updateSecurityPolicies',
                              f.updateSecurityPolicies.map((x, j) =>
                                j === i ? { ...x, allowedTypes: ev.target.value } : x,
                              ),
                            )
                          }
                        />
                        <Button
                          size="sm"
                          onClick={() =>
                            set(
                              'updateSecurityPolicies',
                              f.updateSecurityPolicies.filter((_, j) => j !== i),
                            )
                          }
                        >
                          Remove
                        </Button>
                      </div>
                    ))}
                    <div>
                      <Button
                        onClick={() =>
                          set('updateSecurityPolicies', [
                            ...f.updateSecurityPolicies,
                            { tsigKeyName: '', domain: zone, allowedTypes: 'ANY' },
                          ])
                        }
                      >
                        Add Policy
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </>
      )}
    </Dialog>
  )
}

/**
 * Las cuatro secciones tienen la misma forma: una lista de criterios y una
 * lista de texto que sólo se puede tocar con algunos de ellos.
 */
function Criterio({
  nombre,
  opciones,
  valor,
  bloqueado,
  onCambio,
  lista,
  listaEtiqueta,
  listaEditable,
  onLista,
}: {
  nombre: string
  opciones: { valor: string; etiqueta: string }[]
  valor: string
  bloqueado: boolean
  onCambio: (v: string) => void
  lista: string
  listaEtiqueta: string
  listaEditable: boolean
  onLista: (v: string) => void
}) {
  return (
    <>
      <div className={styles.filaCtl}>
        {opciones.map((o) => (
          <label key={o.valor} className={styles.chk}>
            <input
              type="radio"
              name={nombre}
              disabled={bloqueado}
              checked={valor === o.valor}
              onChange={() => onCambio(o.valor)}
            />
            {o.etiqueta}
          </label>
        ))}
      </div>
      <Field label={listaEtiqueta}>
        {(id) => (
          <Textarea
            id={id}
            mono
            className={styles.area}
            disabled={!listaEditable}
            value={lista}
            onChange={(ev) => onLista(ev.target.value)}
          />
        )}
      </Field>
    </>
  )
}
