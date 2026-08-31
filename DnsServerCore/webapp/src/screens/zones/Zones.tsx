import { useState } from 'react'
import type { ResourceRecord, ZonaDeRegistros } from '../../api/registros'
import { Confirm } from '../../ui/Confirmar'
import { ListaZonas } from './ListaZonas'
import { RegistrosZona } from './RegistrosZona'
import { AddEditRecord } from './modales/AnadirEditarRegistro'
import { AddZone } from './modales/AnadirZona'
import { ClonarZona } from './modales/ClonarZona'
import { ConvertZone } from './modales/ConvertirZona'
import { DesfirmarZona } from './modales/DesfirmarZona'
import { FirmarZona } from './modales/FirmarZona'
import { ImportarZona } from './modales/ImportarZona'
import { OpcionesZona } from './modales/OpcionesZona'
import { PermisosZona } from './modales/PermisosZona'
import { PropiedadesDnssec } from './modales/PropiedadesDnssec'
import { VerDs } from './modales/VerDs'
import type { Notice, Confirmation } from './tipos'
import { Notifier } from '../../ui/Avisador'

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
  const [notice, setAviso] = useState<Notice | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [modal, setModal] = useState<ModalId | null>(null)

  /** The zone the open modal acts on; it may not be the one on screen. */
  const [zonaModal, setZonaModal] = useState('')
  const [modalKind, setTipoModal] = useState('')

  const [recordMode, setModoRegistro] = useState<'add' | 'update'>('add')
  const [zonaDeRegistros, setZonaDeRegistros] = useState<ZonaDeRegistros | null>(null)
  const [records, setRegistros] = useState<ResourceRecord[]>([])
  const [registroOriginal, setRegistroOriginal] = useState<ResourceRecord | null>(null)

  /*
  The expiry TTL left over in the record modal. Upstream reads it from that
  field when DISABLING a record from the row (`updateRecordState`,
  zone.js:6236), so the value survives the modal's closing. It is a bug of
  theirs; it is replicated because the rule is zero behaviour changes.
  */
  const [expiryTtlDelModal, setExpiryTtlDelModal] = useState('')

  const [refrescoLista, setRefrescoLista] = useState(0)
  const [refrescoZona, setRefrescoZona] = useState(0)

  const releerLista = () => setRefrescoLista((n) => n + 1)
  const releerZona = () => setRefrescoZona((n) => n + 1)

  function openModal(id: ModalId, zone: string, type = '') {
    setZonaModal(zone)
    setTipoModal(type)
    setModal(id)
  }

  /** After a mutating modal: refreshes whatever is in front. */
  function hecho(a: Notice) {
    setAviso(a)
    if (open == null) releerLista()
    else releerZona()
  }

  return (
    <>
      <Notifier notice={notice} onCerrar={() => setAviso(null)} />

      {open == null ? (
        <ListaZonas
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onAviso={setAviso}
          onConfirmar={setConfirmation}
          onAnadir={() => openModal('add', '')}
          onAbrir={(z) => {
            setAviso(null)
            setAbierta(z)
          }}
          onImportar={(z) => openModal('import', z)}
          onConvertir={(z, t) => openModal('convert', z, t)}
          onClonar={(z) => openModal('clone', z)}
          onPermisos={(z) => openModal('permissions', z)}
          onOpciones={(z) => openModal('options', z)}
          refresco={refrescoLista}
        />
      ) : (
        <RegistrosZona
          zone={open}
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onVolver={() => {
            setAbierta(null)
            releerLista()
          }}
          onAviso={setAviso}
          onConfirmar={setConfirmation}
          onAnadirRegistro={(zone, regs) => {
            setModoRegistro('add')
            setZonaDeRegistros(zone)
            setRegistros(regs)
            setRegistroOriginal(null)
            openModal('record', open)
          }}
          onEditarRegistro={(zone, record, regs) => {
            setModoRegistro('update')
            setZonaDeRegistros(zone)
            setRegistros(regs)
            setRegistroOriginal(record)
            openModal('record', open)
          }}
          onImportar={(z) => openModal('import', z)}
          onConvertir={(z, t) => openModal('convert', z, t)}
          onClonar={(z) => openModal('clone', z)}
          onPermisos={(z) => openModal('permissions', z)}
          onOpciones={(z) => openModal('options', z)}
          onFirmar={(z) => openModal('sign', z)}
          onDesfirmar={(z) => openModal('unsign', z)}
          onVerDs={(z) => openModal('viewds', z)}
          onPropiedadesDnssec={(z) => openModal('dnssec', z)}
          refresco={refrescoZona}
          expiryTtlDelModal={expiryTtlDelModal}
        />
      )}

      <Confirm
        open={confirmation !== null}
        titulo={confirmation?.titulo ?? ''}
        text={confirmation?.text}
        etiqueta={confirmation?.etiqueta ?? ''}
        variante={confirmation?.peligro ? 'danger' : 'primary'}
        onCerrar={() => setConfirmation(null)}
        onConfirmar={() => confirmation?.action()}
      />

      <AddZone
        open={modal === 'add'}
        token={token}
        node={node}
        useSoaSerialDateScheme={useSoaSerialDateScheme}
        dnssecValidation={dnssecValidation}
        onCerrar={() => setModal(null)}
        onCreated={(domain, a) => {
          // Upstream opens the newly created zone, it does not go back to the list.
          setAbierta(domain === '' ? '.' : domain)
          setAviso(a)
        }}
      />

      <ImportarZona
        zone={zonaModal}
        open={modal === 'import'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <ClonarZona
        zone={zonaModal}
        open={modal === 'clone'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <ConvertZone
        zone={zonaModal}
        sourceType={modalKind}
        open={modal === 'convert'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <OpcionesZona
        zone={zonaModal}
        open={modal === 'options'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <PermisosZona
        zone={zonaModal}
        open={modal === 'permissions'}
        token={token}
        node={node}
        canModify={canModify}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <FirmarZona
        zone={zonaModal}
        open={modal === 'sign'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <DesfirmarZona
        zone={zonaModal}
        open={modal === 'unsign'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <VerDs
        zone={zonaModal}
        open={modal === 'viewds'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
      />

      <PropiedadesDnssec
        zone={zonaModal}
        open={modal === 'dnssec'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onConfirmar={setConfirmation}
        onCambio={releerZona}
      />

      <AddEditRecord
        open={modal === 'record'}
        mode={recordMode}
        zone={zonaModal}
        zoneInfo={zonaDeRegistros}
        records={records}
        original={registroOriginal}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
        onExpiryTtl={setExpiryTtlDelModal}
      />
    </>
  )
}

