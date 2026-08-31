import { useCallback, useEffect, useRef, useState } from 'react'
import {
  addDomain,
  deleteDomain,
  deleteCacheNode,
  parentDomain,
  exportDomains,
  importDomains,
  cleanList,
  listNode,
  flushCache,
  flushList,
  type List,
  type DomainList,
  type ListNode,
} from '../../api/zonelists'
import { Button } from '../../ui/Button'
import { Confirm } from '../../ui/Confirm'
import { Dialog } from '../../ui/Dialog'
import { Field, Input, LabeledTextarea } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { Tree } from './Tree'
import { ResourceRecords } from './Records'
import styles from './Lists.module.css'
import { noticeFromFailure, type Notice } from '../../lib/notice'
import { Notifier } from '../../ui/Notifier'

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
  title: string
  text: string
  label: string
  action: () => Promise<void>
}

const TITLE: Record<List, string> = { cache: 'Cache', allowed: 'Allowed', blocked: 'Blocked' }

/*
`importAllowedZones` / `importBlockedZones` (other-zones.js:589-661). The
empty-list alert goes INSIDE the modal, not on the page: upstream passes
`showAlert` the modal's own `divImportAllowedZonesAlert`.
*/
function Import({
  list,
  open,
  token,
  onClose,
  onHecho,
}: {
  list: DomainList
  open: boolean
  token: string | null
  onClose: () => void
  onHecho: (a: Notice) => void
}) {
  const [text, setTexto] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)
  const area = useRef<HTMLTextAreaElement>(null)

  const esAllowed = list === 'allowed'
  const title = esAllowed ? 'Import Allowed Zones' : 'Import Blocked Zones'
  const label = esAllowed ? 'Allowed Zones' : 'Blocked Zones'
  const intro = esAllowed
    ? 'Enter domain names one below other to import into Allowed Zone:'
    : 'Enter domain names one below other to import into blocked zone:'

  // `resetImport*Modal`: on opening, the modal starts clean and with the focus inside.
  useEffect(() => {
    if (open) {
      setTexto('')
      setNotice(null)
      area.current?.focus()
    }
  }, [open])

  async function runImport() {
    const zones = cleanList(text)

    if (zones.length === 0 || zones === ',') {
      setNotice({
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
    const outcome = await importDomains(list, token, zones)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
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
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={title}
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void runImport()}>
            Import
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <p className={styles.parrafo}>{intro}</p>
      <LabeledTextarea
        label={label}
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
  const [node, setNode] = useState<ListNode | null>(null)
  const [field, setField] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [importAbierto, setImportAbierto] = useState(false)
  const [busy, setBusy] = useState(false)
  const entry = useRef<HTMLInputElement>(null)

  const esCache = list === 'cache'
  const domainList = list as DomainList

  const load = useCallback(
    async (domain: string, up?: boolean) => {
      const outcome = await listNode(list, token, domain, up ? 'up' : undefined)
      if (outcome.kind === 'ok') {
        setNode(outcome.data)
        return
      }
      // Upstream's error handler leaves the list where it was and draws the
      // server's errorMessage; the same here.
      setNotice(noticeFromFailure(outcome))
    },
    [list, token],
  )

  useEffect(() => {
    void load('')
  }, [load])

  /** Wraps a mutation: runs it, and on failure draws the server's error. */
  async function mutate(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Notice,
    after: () => Promise<void>,
  ) {
    setBusy(true)
    const outcome = await fn()
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    await after()
    setNotice(exito)
  }

  const domain = node?.domain ?? ''
  const nodeTitle = domain === '' ? '<ROOT>' : (node?.domainIdn ?? domain)
  const zones = node?.zones ?? []
  const records = node?.records ?? []

  // Cache: Delete hangs off the NODE. Allowed/Blocked: off there being records.
  const mayDelete = esCache ? domain !== '' : records.length > 0

  function navegar(d: string, up?: boolean) {
    void load(d, up)
  }

  // ---- Cache actions ------------------------------------------------------

  function pedirFlushCache() {
    setConfirmation({
      title: 'Flush Cache',
      text: 'Are you sure to flush the DNS Server cache?',
      label: 'Flush Cache',
      action: () =>
        mutate(
          () => flushCache(token),
          {
            type: 'success',
            title: 'Flushed!',
            text: 'DNS Server cache was flushed successfully.',
          },
          // Upstream leaves the list at `<ROOT>` and hides the viewer.
          () => load(''),
        ),
    })
  }

  function askDeleteCacheNode() {
    setConfirmation({
      title: 'Delete Cached Zone',
      text: `Are you sure you want to delete the cached zone '${nodeTitle}' and all its records?`,
      label: 'Delete',
      action: () =>
        mutate(
          () => deleteCacheNode(token, nodeTitle),
          {
            type: 'success',
            title: 'Deleted!',
            text: `Cached zone '${nodeTitle}' was deleted successfully.`,
          },
          () => load(parentDomain(nodeTitle) ?? '', true),
        ),
    })
  }

  // ---- Allowed and Blocked actions ----------------------------------------

  async function add() {
    const domain = field

    // The alert goes BEFORE any call, and leaves the focus in the field:
    // other-zones.js:171-176 and 348-353.
    if (domain === '') {
      setNotice({
        type: 'warning',
        title: 'Missing!',
        text:
          domainList === 'allowed'
            ? 'Please enter a domain name to allow.'
            : 'Please enter a domain name to block.',
      })
      entry.current?.focus()
      return
    }

    await mutate(
      () => addDomain(domainList, token, domain),
      domainList === 'allowed'
        ? {
            type: 'success',
            title: 'Allowed!',
            text: `Domain '${domain}' was added to Allowed Zone successfully.`,
          }
        : {
            type: 'success',
            title: 'Blocked!',
            text: `Domain '${domain}' was added to Blocked Zone successfully.`,
          },
      async () => {
        setField('')
        await load(domain)
      },
    )
  }

  function askDeleteDomain() {
    const esAllowed = domainList === 'allowed'
    setConfirmation({
      title: esAllowed ? 'Delete Allowed Zone' : 'Delete Blocked Zone',
      text: esAllowed
        ? `Are you sure you want to delete the allowed zone '${nodeTitle}'?`
        : `Are you sure you want to delete the blocked zone '${nodeTitle}'?`,
      label: 'Delete',
      action: () =>
        mutate(
          () => deleteDomain(domainList, token, nodeTitle),
          esAllowed
            ? {
                type: 'success',
                title: 'Deleted!',
                text: `Domain '${nodeTitle}' was deleted from Allowed Zone successfully.`,
              }
            : {
                type: 'success',
                title: 'Deleted!',
                text: `Blocked zone '${nodeTitle}' was deleted successfully.`,
              },
          () => load(parentDomain(nodeTitle) ?? '', true),
        ),
    })
  }

  function askFlushList() {
    const esAllowed = domainList === 'allowed'
    setConfirmation({
      title: esAllowed ? 'Flush Allowed Zone' : 'Flush Blocked Zone',
      text: esAllowed
        ? 'Are you sure you want to flush the entire Allowed zone?'
        : 'Are you sure you want to flush the entire Blocked zone?',
      label: 'Flush',
      action: () =>
        mutate(
          () => flushList(domainList, token),
          esAllowed
            ? { type: 'success', title: 'Flushed!', text: 'Allowed zone was flushed successfully.' }
            : { type: 'success', title: 'Flushed!', text: 'Blocked zone was flushed successfully.' },
          () => load(''),
        ),
    })
  }

  async function runExport() {
    setBusy(true)
    const r = await exportDomains(domainList, token)
    setBusy(false)
    if (!r.ok) return
    setNotice({
      type: 'success',
      title: 'Exported!',
      text:
        domainList === 'allowed'
          ? 'Allowed zones were exported successfully.'
          : 'Blocked zones were exported successfully.',
    })
  }

  return (
    <>
      <SectionHeader
        title={TITLE[list]}
        actions={<>{esCache ? (
            <Button variant="danger" disabled={busy} onClick={pedirFlushCache}>
              Flush Cache
            </Button>
          ) : (
            <>
              <Button variant="primary" disabled={busy} onClick={() => void add()}>
                {domainList === 'allowed' ? 'Allow' : 'Block'}
              </Button>
              <Button disabled={busy} onClick={() => setImportAbierto(true)}>
                Import
              </Button>
              <Button disabled={busy} onClick={() => void runExport()}>
                Export
              </Button>
              <Button variant="danger" disabled={busy} onClick={askFlushList}>
                Flush
              </Button>
            </>
          )}</>}
      />

      <Notifier notice={notice} onClose={() => setNotice(null)} />

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
                    onChange={(e) => setField(e.target.value)}
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
              {records.length} records at <span className={styles.mono}>{nodeTitle}</span>
            </span>
            <div className={styles.countActs}>
              <Button size="sm" onClick={() => navegar(domain)}>
                Refresh
              </Button>
              {mayDelete && (
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={esCache ? askDeleteCacheNode : askDeleteDomain}
                >
                  Delete
                </Button>
              )}
            </div>
          </div>

          {records.length > 0 ? (
            <ResourceRecords records={records} withDnssec={esCache} node={domain} />
          ) : (
            <Empty title="No records at this node">
              {zones.length > 0
                ? 'This node only contains sub-domains. Open one in the tree to see its records.'
                : 'This node has no records and no sub-domains.'}
            </Empty>
          )}
        </div>
      </div>

      <Confirm
        open={confirmation !== null}
        title={confirmation?.title ?? ''}
        text={confirmation?.text}
        label={confirmation?.label ?? ''}
        onClose={() => setConfirmation(null)}
        onConfirm={() => confirmation?.action()}
      />

      {!esCache && (
        <Import
          list={domainList}
          open={importAbierto}
          token={token}
          onClose={() => setImportAbierto(false)}
          onHecho={setNotice}
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
