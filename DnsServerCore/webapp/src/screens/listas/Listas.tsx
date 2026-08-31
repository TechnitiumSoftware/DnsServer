import { useCallback, useEffect, useRef, useState } from 'react'
import {
  anadirDominio,
  borrarDominio,
  borrarNodoCache,
  dominioPadre,
  exportarDominios,
  importarDominios,
  limpiarLista,
  listarNodo,
  vaciarCache,
  vaciarLista,
  type List,
  type ListaDominios,
  type NodoLista,
} from '../../api/zonelists'
import { Button } from '../../ui/Button'
import { Confirmar } from '../../ui/Confirmar'
import { Dialog } from '../../ui/Dialog'
import { Field, Input, LabeledTextarea } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { Tree } from './Arbol'
import { ResourceRecords } from './Registros'
import styles from './Listas.module.css'
import { avisoDeFallo, type Aviso } from '../../lib/aviso'
import { Avisador } from '../../ui/Avisador'

/*
Cache, Allowed and Blocked. A single screen because in upstream they are three
copies of the same code (`refreshCachedZonesList`, `refreshAllowedZonesList` and
`refreshBlockedZonesList` are the same function three times, other-zones.js).

What really changes between the three are the TEXTS —and they are not
interchangeable: deleting in Allowed says "Domain 'x' was deleted from Allowed
Zone successfully." and deleting in Blocked says "Blocked zone 'x' was deleted
successfully.". That is why each sentence is written out whole in its place
instead of being composed from templates: a template would have made the
asymmetry uniform and would have changed a text.

And what changes in the BEHAVIOUR is when the Delete button shows: in Cache it
depends on being outside the root (other-zones.js:143-152) and in Allowed and
Blocked on the node having records (lines 319-327). It is replicated as it is.
*/


interface Confirmation {
  titulo: string
  text: string
  etiqueta: string
  action: () => Promise<void>
}

const TITULO: Record<List, string> = { cache: 'Cache', allowed: 'Allowed', blocked: 'Blocked' }

/*
`importAllowedZones` / `importBlockedZones` (other-zones.js:589-661). The
empty-list alert goes INSIDE the modal, not on the page: upstream passes
`showAlert` the modal's own `divImportAllowedZonesAlert`.
*/
function Importar({
  list,
  abierto,
  token,
  onCerrar,
  onHecho,
}: {
  list: ListaDominios
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const [text, setTexto] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)
  const area = useRef<HTMLTextAreaElement>(null)

  const esAllowed = list === 'allowed'
  const titulo = esAllowed ? 'Import Allowed Zones' : 'Import Blocked Zones'
  const etiqueta = esAllowed ? 'Allowed Zones' : 'Blocked Zones'
  const intro = esAllowed
    ? 'Enter domain names one below other to import into Allowed Zone:'
    : 'Enter domain names one below other to import into blocked zone:'

  // `resetImport*Modal`: on opening, the modal starts clean and with the focus inside.
  useEffect(() => {
    if (abierto) {
      setTexto('')
      setAviso(null)
      area.current?.focus()
    }
  }, [abierto])

  async function importar() {
    const zones = limpiarLista(text)

    if (zones.length === 0 || zones === ',') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text: esAllowed
          ? 'Please enter allowed zones to import.'
          : 'Please enter blocked zones to import.',
      })
      area.current?.focus()
      return
    }

    setBusy(true)
    const outcome = await importarDominios(list, token, zones)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    onCerrar()
    onHecho({
      type: 'success',
      title: 'Imported!',
      text: esAllowed
        ? 'Domain names were imported into allowed zone successfully.'
        : 'Domain names were imported into blocked zone successfully.',
    })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title={titulo}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void importar()}>
            Import
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      <p className={styles.parrafo}>{intro}</p>
      <LabeledTextarea
        label={etiqueta}
        ref={area}
        mono
        className={styles.area}
        spellCheck={false}
        value={text}
        onChange={(e) => setTexto(e.target.value)}
      />
    </Dialog>
  )
}

export function Lists({ list, token }: { list: List; token: string | null }) {
  const [node, setNodo] = useState<NodoLista | null>(null)
  const [field, setCampo] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [importAbierto, setImportAbierto] = useState(false)
  const [busy, setBusy] = useState(false)
  const entry = useRef<HTMLInputElement>(null)

  const esCache = list === 'cache'
  const listaDominios = list as ListaDominios

  const cargar = useCallback(
    async (domain: string, up?: boolean) => {
      const outcome = await listarNodo(list, token, domain, up ? 'up' : undefined)
      if (outcome.kind === 'ok') {
        setNodo(outcome.data)
        return
      }
      // Upstream's error handler leaves the list where it was and draws the
      // server's errorMessage; the same here.
      setAviso(avisoDeFallo(outcome))
    },
    [list, token],
  )

  useEffect(() => {
    void cargar('')
  }, [cargar])

  /** Wraps a mutation: runs it, and on failure draws the server's error. */
  async function mutar(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
    despues: () => Promise<void>,
  ) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    await despues()
    setAviso(exito)
  }

  const domain = node?.domain ?? ''
  const tituloNodo = domain === '' ? '<ROOT>' : (node?.domainIdn ?? domain)
  const zones = node?.zones ?? []
  const records = node?.records ?? []

  // Cache: Delete hangs off the NODE. Allowed/Blocked: off there being records.
  const puedeBorrar = esCache ? domain !== '' : records.length > 0

  function navegar(d: string, up?: boolean) {
    void cargar(d, up)
  }

  // ---- acciones de Cache -------------------------------------------------

  function pedirFlushCache() {
    setConfirmation({
      titulo: 'Flush Cache',
      text: 'Are you sure to flush the DNS Server cache?',
      etiqueta: 'Flush Cache',
      action: () =>
        mutar(
          () => vaciarCache(token),
          {
            type: 'success',
            title: 'Flushed!',
            text: 'DNS Server cache was flushed successfully.',
          },
          // Upstream leaves the list at `<ROOT>` and hides the viewer.
          () => cargar(''),
        ),
    })
  }

  function pedirBorrarNodoCache() {
    setConfirmation({
      titulo: 'Delete Cached Zone',
      text: `Are you sure you want to delete the cached zone '${tituloNodo}' and all its records?`,
      etiqueta: 'Delete',
      action: () =>
        mutar(
          () => borrarNodoCache(token, tituloNodo),
          {
            type: 'success',
            title: 'Deleted!',
            text: `Cached zone '${tituloNodo}' was deleted successfully.`,
          },
          () => cargar(dominioPadre(tituloNodo) ?? '', true),
        ),
    })
  }

  // ---- acciones de Allowed y Blocked -------------------------------------

  async function anadir() {
    const dominio = field

    // The alert goes BEFORE any call, and leaves the focus in the field:
    // other-zones.js:171-176 y 348-353.
    if (dominio === '') {
      setAviso({
        type: 'warning',
        title: 'Missing!',
        text:
          listaDominios === 'allowed'
            ? 'Please enter a domain name to allow.'
            : 'Please enter a domain name to block.',
      })
      entry.current?.focus()
      return
    }

    await mutar(
      () => anadirDominio(listaDominios, token, dominio),
      listaDominios === 'allowed'
        ? {
            type: 'success',
            title: 'Allowed!',
            text: `Domain '${dominio}' was added to Allowed Zone successfully.`,
          }
        : {
            type: 'success',
            title: 'Blocked!',
            text: `Domain '${dominio}' was added to Blocked Zone successfully.`,
          },
      async () => {
        setCampo('')
        await cargar(dominio)
      },
    )
  }

  function pedirBorrarDominio() {
    const esAllowed = listaDominios === 'allowed'
    setConfirmation({
      titulo: esAllowed ? 'Delete Allowed Zone' : 'Delete Blocked Zone',
      text: esAllowed
        ? `Are you sure you want to delete the allowed zone '${tituloNodo}'?`
        : `Are you sure you want to delete the blocked zone '${tituloNodo}'?`,
      etiqueta: 'Delete',
      action: () =>
        mutar(
          () => borrarDominio(listaDominios, token, tituloNodo),
          esAllowed
            ? {
                type: 'success',
                title: 'Deleted!',
                text: `Domain '${tituloNodo}' was deleted from Allowed Zone successfully.`,
              }
            : {
                type: 'success',
                title: 'Deleted!',
                text: `Blocked zone '${tituloNodo}' was deleted successfully.`,
              },
          () => cargar(dominioPadre(tituloNodo) ?? '', true),
        ),
    })
  }

  function pedirFlushLista() {
    const esAllowed = listaDominios === 'allowed'
    setConfirmation({
      titulo: esAllowed ? 'Flush Allowed Zone' : 'Flush Blocked Zone',
      text: esAllowed
        ? 'Are you sure you want to flush the entire Allowed zone?'
        : 'Are you sure you want to flush the entire Blocked zone?',
      etiqueta: 'Flush',
      action: () =>
        mutar(
          () => vaciarLista(listaDominios, token),
          esAllowed
            ? { type: 'success', title: 'Flushed!', text: 'Allowed zone was flushed successfully.' }
            : { type: 'success', title: 'Flushed!', text: 'Blocked zone was flushed successfully.' },
          () => cargar(''),
        ),
    })
  }

  async function exportar() {
    setBusy(true)
    const r = await exportarDominios(listaDominios, token)
    setBusy(false)
    if (!r.ok) return
    setAviso({
      type: 'success',
      title: 'Exported!',
      text:
        listaDominios === 'allowed'
          ? 'Allowed zones were exported successfully.'
          : 'Blocked zones were exported successfully.',
    })
  }

  return (
    <>
      <SectionHeader
        titulo={TITULO[list]}
        actions={<>{esCache ? (
            <Button variant="danger" disabled={busy} onClick={pedirFlushCache}>
              Flush Cache
            </Button>
          ) : (
            <>
              <Button variant="primary" disabled={busy} onClick={() => void anadir()}>
                {listaDominios === 'allowed' ? 'Allow' : 'Block'}
              </Button>
              <Button disabled={busy} onClick={() => setImportAbierto(true)}>
                Import
              </Button>
              <Button disabled={busy} onClick={() => void exportar()}>
                Export
              </Button>
              <Button variant="danger" disabled={busy} onClick={pedirFlushLista}>
                Flush
              </Button>
            </>
          )}</>}
      />

      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      <div className={styles.brow}>
        <div className={styles.tree}>
          <div className={styles.browse}>
            <div className={styles.browseRow}>
              {/* The field is called "Domain" and the button "Browse". Upstream puts
                  no label here —only the `placeholder`— so this one is an
                  addition of ours and can be called whatever suits; what it
                  cannot be called is the same as the button next to it, which
                  does carry upstream's literal. */}
              <Field label="Domain">
                {(id) => (
                  <Input
                    id={id}
                    ref={entry}
                    mono
                    placeholder="example.com"
                    value={field}
                    onChange={(e) => setCampo(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') navegar(field)
                    }}
                  />
                )}
              </Field>
              {/* "Browse" and not "Go": it is upstream's literal on all three list
                  screens (Cache, Allowed and Blocked), and it also says better
                  what it does —it takes you to that point of the tree, it sends
                  nothing. */}
              <Button variant="primary" onClick={() => navegar(field)}>
                Browse
              </Button>
            </div>
          </div>
          {/* The count lives in the count bar, like the records one: in the
              header it looked exactly like a status pill. */}
          <div className={styles.count}>
            <span>{zones.length === 1 ? '1 zone' : `${zones.length} zones`}</span>
          </div>
          <Tree
            domain={domain}
            domainIdn={node?.domainIdn}
            zones={zones}
            onNavegar={navegar}
          />
        </div>

        <div>
          <div className={styles.count}>
            <span>
              {records.length} records at <span className={styles.mono}>{tituloNodo}</span>
            </span>
            <div className={styles.countActs}>
              <Button size="sm" onClick={() => navegar(domain)}>
                Refresh
              </Button>
              {puedeBorrar && (
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={esCache ? pedirBorrarNodoCache : pedirBorrarDominio}
                >
                  Delete
                </Button>
              )}
            </div>
          </div>

          {records.length > 0 ? (
            <ResourceRecords records={records} conDnssec={esCache} node={domain} />
          ) : (
            <Empty titulo="No records at this node">
              {zones.length > 0
                ? 'This node only contains sub-domains. Open one in the tree to see its records.'
                : 'This node has no records and no sub-domains.'}
            </Empty>
          )}
        </div>
      </div>

      <Confirmar
        abierto={confirmation !== null}
        titulo={confirmation?.titulo ?? ''}
        text={confirmation?.text}
        etiqueta={confirmation?.etiqueta ?? ''}
        onCerrar={() => setConfirmation(null)}
        onConfirmar={() => confirmation?.action()}
      />

      {!esCache && (
        <Importar
          list={listaDominios}
          abierto={importAbierto}
          token={token}
          onCerrar={() => setImportAbierto(false)}
          onHecho={setAviso}
        />
      )}
    </>
  )
}

export function Cache({ token }: { token: string | null }) {
  return <Lists list="cache" token={token} />
}

export function Allowed({ token }: { token: string | null }) {
  return <Lists list="allowed" token={token} />
}

export function Blocked({ token }: { token: string | null }) {
  return <Lists list="blocked" token={token} />
}
