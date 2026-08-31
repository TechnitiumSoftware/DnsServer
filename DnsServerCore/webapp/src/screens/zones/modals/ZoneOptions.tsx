import { useEffect, useState } from 'react'
import { getZoneOptions, setZoneOptions, type ZoneOptions as Respuesta } from '../../../api/zones'
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
  buildOptionsBody,
  optionsState,
  formFromOptions,
  notifyWithList,
  type OptionsState,
  type OptionsForm,
  type OptionsTab,
} from '../options'
import type { Notice } from '../types'
import styles from '../Zones.module.css'
import { Externo } from '../../../ui/Externo'
import { RFC_ZONEMD } from '../references'
import frm from '../../../ui/Form.module.css'
import { GroupRow } from '../../../ui/Form'
import { Segmented } from '../../../ui/Segmented'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalZoneOptions` (zone.js:1524 and 2380). Five tabs and a visibility matrix
that `opciones.ts` decides.

**The form is A SINGLE ONE**: "Save" sends the fields of all five tabs wherever
you are, just as in Settings. Chopping it up per tab would change what gets
saved.

And for that very reason, if the validation fails on a tab that is not in front,
it jumps to it: it is the same deliberate deviation decided in Settings, and for
the same reason — with one panel mounted at a time, without the jump the alert
would be impossible to resolve.
*/

export function ZoneOptions({
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
  const [respuesta, setRespuesta] = useState<Respuesta | null>(null)
  const [f, setF] = useState<OptionsForm | null>(null)
  const [pestana, setPestana] = useState<OptionsTab>('General')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setLoading(true)
    void getZoneOptions(token, zone, node).then((r) => {
      setLoading(false)
      if (r == null) {
        setNotice({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setRespuesta(r)
      setF(formFromOptions(r))
      setPestana(optionsState(r).pestanaInicial)
    })
  }, [open, token, zone, node])

  const e: OptionsState | null = respuesta ? optionsState(respuesta) : null

  const set = <K extends keyof OptionsForm>(k: K, value: OptionsForm[K]) =>
    setF((prev) => (prev == null ? prev : { ...prev, [k]: value }))

  async function save() {
    if (f == null || respuesta == null) return

    const r = buildOptionsBody(f, respuesta.type)
    if ('error' in r) {
      setPestana(r.error.tab)
      setNotice({ type: 'warning', title: r.error.title, text: r.error.text })
      return
    }

    setBusy(true)
    const outcome = await setZoneOptions(token, { zone, ...r.body }, node)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    onHecho({ type: 'success', title: 'Options Saved!', text: 'Zone options were saved successfully.' })
  }

  const tsigDisponibles = respuesta?.availableTsigKeyNames ?? []
  const catalogosDisponibles = respuesta?.availableCatalogZoneNames ?? []

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="medium"
      title={`Zone Options - ${zone === '.' ? '<root>' : zone}`}
      actions={
        <>
          <Button variant="primary" disabled={busy || f == null} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      {loading || f == null || e == null ? (
        <Loading>Loading zone options…</Loading>
      ) : (
        <>
          {/* A segmented control, not the pagination button's class: a tab
              and a page number are not the same thing. */}
          <Segmented
            comoPestanas
            label="Zone options"
            options={PESTANAS.filter((t) => e.pestanas.includes(t.id)).map((t) => ({
              id: t.id,
              label: t.label,
            }))}
            active={pestana}
            onChoose={setPestana}
          />

          <div className={styles.fields}>
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
                          disabled={e.overrideLocked}
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
                          disabled={e.overrideLocked}
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
                          disabled={e.overrideLocked}
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
                          disabled={e.primaryServerLocked}
                          value={f.primaryNameServerAddresses}
                          onChange={(ev) => set('primaryNameServerAddresses', ev.target.value)}
                        />
                      )}
                    </Field>
                    <div className={styles.help}>
                      {e.servidorPrimarioObligatorio
                        ? 'Enter the primary name server addresses to sync the zone from.'
                        : 'Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.'}
                    </div>

                    {e.protocoloXfr && (
                      <GroupRow modal label="Zone Transfer Protocol">
                        {PROTOCOLOS_XFR.map((x) => (
                          <label key={x.value} className={styles.chk}>
                            <input
                              type="radio"
                              name="zoneOptionsXfr"
                              disabled={e.primaryServerLocked}
                              checked={f.primaryZoneTransferProtocol === x.value}
                              onChange={() => set('primaryZoneTransferProtocol', x.value)}
                            />
                            {x.label}
                          </label>
                        ))}
                      </GroupRow>
                    )}

                    {e.tsigDelPrimario && (
                      <Field label="TSIG Key Name (Optional)">
                        {(id) => (
                          <Select
                            id={id}
                            disabled={e.primaryServerLocked}
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

                    {e.validateZone && (
                      <label className={styles.chk}>
                        <input
                          type="checkbox"
                          disabled={e.primaryServerLocked}
                          checked={f.validateZone}
                          onChange={(ev) => set('validateZone', ev.target.checked)}
                        />
                        Use <Externo href={RFC_ZONEMD}>ZONEMD</Externo> to Validate Zone
                      </label>
                    )}
                  </>
                )}
              </>
            )}

            {pestana === 'Query Access' && (
              <Criterio
                name="zoneOptionsQueryAccess"
                options={ACCESOS_CONSULTA.filter(
                  (o) => e.queryAccessConNameServers || !o.value.includes('ZoneNameServers'),
                )}
                value={f.queryAccess}
                locked={e.queryAccessLocked}
                onCambio={(v) => set('queryAccess', v)}
                list={f.queryAccessNetworkACL}
                listLabel="Network Access Control List (ACL)"
                editableList={aclEditable(f.queryAccess) && !e.queryAccessLocked}
                onList={(v) => set('queryAccessNetworkACL', v)}
              />
            )}

            {pestana === 'Zone Transfer' && (
              <>
                <Criterio
                  name="zoneOptionsZoneTransfer"
                  options={TRANSFERENCIAS.filter(
                    (o) => e.zoneTransferConNameServers || !o.value.includes('ZoneNameServers'),
                  )}
                  value={f.zoneTransfer}
                  locked={e.zoneTransferLocked}
                  onCambio={(v) => set('zoneTransfer', v)}
                  list={f.zoneTransferNetworkACL}
                  listLabel="Network Access Control List (ACL)"
                  editableList={aclEditable(f.zoneTransfer) && !e.zoneTransferLocked}
                  onList={(v) => set('zoneTransferNetworkACL', v)}
                />
                <Field label="Zone Transfer TSIG Key Names">
                  {(id) => (
                    <Textarea
                      id={id}
                      mono
                      className={styles.area}
                      disabled={e.zoneTransferLocked}
                      value={f.zoneTransferTsigKeyNames}
                      onChange={(ev) => set('zoneTransferTsigKeyNames', ev.target.value)}
                    />
                  )}
                </Field>
                {/* "Quick Add" only adds to the list above: it sends nothing. */}
                <Field label="Quick Add">
                  {(id) => (
                    <Select
                      id={id}
                      disabled={e.zoneTransferLocked}
                      value=""
                      onChange={(ev) => {
                        const v = ev.target.value
                        if (v === '') return
                        const current = f.zoneTransferTsigKeyNames
                        set('zoneTransferTsigKeyNames', current === '' ? v : `${current}\n${v}`)
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
                  name="zoneOptionsNotify"
                  options={NOTIFICACIONES.filter((o) => {
                    if (o.value === 'SeparateNameServersForCatalogAndMemberZones') return e.notifySeparados
                    if (o.value === 'ZoneNameServers' || o.value === 'BothZoneAndSpecifiedNameServers') {
                      return e.notifyConNameServers
                    }
                    return true
                  })}
                  value={f.notify}
                  locked={false}
                  onCambio={(v) => set('notify', v)}
                  list={f.notifyNameServers}
                  listLabel="Specified Name Servers"
                  editableList={notifyWithList(f.notify)}
                  onList={(v) => set('notifyNameServers', v)}
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
                  <Alert type="warning" title="Notify Failed For:">
                    {(respuesta.notifyFailedFor ?? []).join(', ')}
                  </Alert>
                )}
              </>
            )}

            {pestana === 'Dynamic Updates' && (
              <>
                <Criterio
                  name="zoneOptionsUpdate"
                  options={ACTUALIZACIONES.filter(
                    (o) => e.updateConNameServers || !o.value.includes('ZoneNameServers'),
                  )}
                  value={f.update}
                  locked={false}
                  onCambio={(v) => set('update', v)}
                  list={f.updateNetworkACL}
                  listLabel="Network Access Control List (ACL)"
                  editableList={aclEditable(f.update)}
                  onList={(v) => set('updateNetworkACL', v)}
                />

                {e.securityPolicies && (
                  <div className={styles.group}>
                    <div className={styles.groupTitle}>Security Policy</div>
                    {f.updateSecurityPolicies.map((row, i) => (
                      <div key={i} className={styles.inline}>
                        <Select
                          aria-label={`TSIG key name ${i + 1}`}
                          value={row.tsigKeyName}
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
                          value={row.domain}
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
                          value={row.allowedTypes}
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
 * All four sections have the same shape: a list of criteria and a text list that
 * can only be touched with some of them.
 */
function Criterio({
  name,
  options,
  value,
  locked,
  onCambio,
  list,
  listLabel,
  editableList,
  onList,
}: {
  name: string
  options: { value: string; label: string }[]
  value: string
  locked: boolean
  onCambio: (v: string) => void
  list: string
  listLabel: string
  editableList: boolean
  onList: (v: string) => void
}) {
  return (
    <>
      <div className={frm.mrowCtl}>
        {options.map((o) => (
          <label key={o.value} className={styles.chk}>
            <input
              type="radio"
              name={name}
              disabled={locked}
              checked={value === o.value}
              onChange={() => onCambio(o.value)}
            />
            {o.label}
          </label>
        ))}
      </div>
      <Field label={listLabel}>
        {(id) => (
          <Textarea
            id={id}
            mono
            className={styles.area}
            disabled={!editableList}
            value={list}
            onChange={(ev) => onList(ev.target.value)}
          />
        )}
      </Field>
    </>
  )
}
