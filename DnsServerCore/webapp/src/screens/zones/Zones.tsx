import { useState } from 'react'
import type { ResourceRecord, ZoneDetails } from '../../api/records'
import { Confirm } from '../../ui/Confirm'
import { ZoneList } from './ZoneList'
import { ZoneRecords } from './ZoneRecords'
import { AddEditRecord } from './modals/AddEditRecord'
import { AddZone } from './modals/AddZone'
import { CloneZone } from './modals/CloneZone'
import { ConvertZone } from './modals/ConvertZone'
import { UnsignZone } from './modals/UnsignZone'
import { SignZone } from './modals/SignZone'
import { ImportZone } from './modals/ImportZone'
import { ZoneOptions } from './modals/ZoneOptions'
import { ZonePermissions } from './modals/ZonePermissions'
import { PropiedadesDnssec } from './modals/DnssecProperties'
import { ViewDs } from './modals/ViewDs'
import type { Notice, Confirmation } from './types'
import { Notifier } from '../../ui/Notifier'

/*
The whole Zones section: the list, a zone's view and the ten modals.

In upstream they are two `div` shown and hidden (`divViewZones` and
`divEditZone`); here it is a state, `abierta`. The rest of the structure is the
same on purpose: same modals, same texts, same steps.

**The alerts live here, not in each screen.** In upstream a `showAlert` with no
container draws them in the global bar, so an action fired from a modal that
closes the modal leaves the alert visible behind it. With the alert inside each
screen that case would be lost.
*/

type ModalId =
  | 'add'
  | 'import'
  | 'clone'
  | 'convert'
  | 'options'
  | 'permissions'
  | 'sign'
  | 'unsign'
  | 'viewds'
  | 'dnssec'
  | 'record'

export interface ZonesProps {
  token: string | null
  node?: string
  canModify: boolean
  canDelete: boolean
  /** They inherit from Settings' global setting for the add modal. */
  useSoaSerialDateScheme?: boolean
  dnssecValidation?: boolean
}

export function Zones({
  token,
  node = '',
  canModify,
  canDelete,
  useSoaSerialDateScheme = false,
  dnssecValidation = false,
}: ZonesProps) {
  const [open, setAbierta] = useState<string | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [modal, setModal] = useState<ModalId | null>(null)

  /** The zone the open modal acts on; it may not be the one on screen. */
  const [modalZone, setModalZone] = useState('')
  const [modalKind, setTipoModal] = useState('')

  const [recordMode, setRecordMode] = useState<'add' | 'update'>('add')
  const [zoneDetails, setZoneDetails] = useState<ZoneDetails | null>(null)
  const [records, setRecords] = useState<ResourceRecord[]>([])
  const [originalRecord, setOriginalRecord] = useState<ResourceRecord | null>(null)

  /*
  The expiry TTL left over in the record modal. Upstream reads it from that
  field when DISABLING a record from the row (`updateRecordState`,
  zone.js:6236), so the value survives the modal's closing. It is a bug of
  theirs; it is replicated because the rule is zero behaviour changes.
  */
  const [expiryTtlDelModal, setExpiryTtlDelModal] = useState('')

  const [listRefresh, setListRefresh] = useState(0)
  const [zoneRefresh, setZoneRefresh] = useState(0)

  const refreshList = () => setListRefresh((n) => n + 1)
  const refreshZone = () => setZoneRefresh((n) => n + 1)

  function openModal(id: ModalId, zone: string, type = '') {
    setModalZone(zone)
    setTipoModal(type)
    setModal(id)
  }

  /** After a mutating modal: refreshes whatever is in front. */
  function done(a: Notice) {
    setNotice(a)
    if (open == null) refreshList()
    else refreshZone()
  }

  return (
    <>
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      {open == null ? (
        <ZoneList
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onNotice={setNotice}
          onConfirm={setConfirmation}
          onAdd={() => openModal('add', '')}
          onOpen={(z) => {
            setNotice(null)
            setAbierta(z)
          }}
          onImport={(z) => openModal('import', z)}
          onConvert={(z, t) => openModal('convert', z, t)}
          onClone={(z) => openModal('clone', z)}
          onPermissions={(z) => openModal('permissions', z)}
          onOptions={(z) => openModal('options', z)}
          refresh={listRefresh}
        />
      ) : (
        <ZoneRecords
          zone={open}
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onVolver={() => {
            setAbierta(null)
            refreshList()
          }}
          onNotice={setNotice}
          onConfirm={setConfirmation}
          onAddRecord={(zone, recs) => {
            setRecordMode('add')
            setZoneDetails(zone)
            setRecords(recs)
            setOriginalRecord(null)
            openModal('record', open)
          }}
          onEditRecord={(zone, record, recs) => {
            setRecordMode('update')
            setZoneDetails(zone)
            setRecords(recs)
            setOriginalRecord(record)
            openModal('record', open)
          }}
          onImport={(z) => openModal('import', z)}
          onConvert={(z, t) => openModal('convert', z, t)}
          onClone={(z) => openModal('clone', z)}
          onPermissions={(z) => openModal('permissions', z)}
          onOptions={(z) => openModal('options', z)}
          onSign={(z) => openModal('sign', z)}
          onUnsign={(z) => openModal('unsign', z)}
          onViewDs={(z) => openModal('viewds', z)}
          onPropiedadesDnssec={(z) => openModal('dnssec', z)}
          refresh={zoneRefresh}
          expiryTtlDelModal={expiryTtlDelModal}
        />
      )}

      <Confirm
        open={confirmation !== null}
        title={confirmation?.title ?? ''}
        text={confirmation?.text}
        label={confirmation?.label ?? ''}
        variant={confirmation?.danger ? 'danger' : 'primary'}
        onClose={() => setConfirmation(null)}
        onConfirm={() => confirmation?.action()}
      />

      <AddZone
        open={modal === 'add'}
        token={token}
        node={node}
        useSoaSerialDateScheme={useSoaSerialDateScheme}
        dnssecValidation={dnssecValidation}
        onClose={() => setModal(null)}
        onCreated={(domain, a) => {
          // Upstream opens the newly created zone, it does not go back to the list.
          setAbierta(domain === '' ? '.' : domain)
          setNotice(a)
        }}
      />

      <ImportZone
        zone={modalZone}
        open={modal === 'import'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <CloneZone
        zone={modalZone}
        open={modal === 'clone'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <ConvertZone
        zone={modalZone}
        sourceType={modalKind}
        open={modal === 'convert'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <ZoneOptions
        zone={modalZone}
        open={modal === 'options'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <ZonePermissions
        zone={modalZone}
        open={modal === 'permissions'}
        token={token}
        node={node}
        canModify={canModify}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <SignZone
        zone={modalZone}
        open={modal === 'sign'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <UnsignZone
        zone={modalZone}
        open={modal === 'unsign'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
      />

      <ViewDs
        zone={modalZone}
        open={modal === 'viewds'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
      />

      <PropiedadesDnssec
        zone={modalZone}
        open={modal === 'dnssec'}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onConfirm={setConfirmation}
        onCambio={refreshZone}
      />

      <AddEditRecord
        open={modal === 'record'}
        mode={recordMode}
        zone={modalZone}
        zoneInfo={zoneDetails}
        records={records}
        original={originalRecord}
        token={token}
        node={node}
        onClose={() => setModal(null)}
        onDone={done}
        onExpiryTtl={setExpiryTtlDelModal}
      />
    </>
  )
}

