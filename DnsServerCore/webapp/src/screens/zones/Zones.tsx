import { useState } from 'react'
import type { Registro, ZonaDeRegistros } from '../../api/registros'
import { Confirmar } from '../../ui/Confirmar'
import { ListaZonas } from './ListaZonas'
import { RegistrosZona } from './RegistrosZona'
import { AnadirEditarRegistro } from './modales/AnadirEditarRegistro'
import { AnadirZona } from './modales/AnadirZona'
import { ClonarZona } from './modales/ClonarZona'
import { ConvertirZona } from './modales/ConvertirZona'
import { DesfirmarZona } from './modales/DesfirmarZona'
import { FirmarZona } from './modales/FirmarZona'
import { ImportarZona } from './modales/ImportarZona'
import { OpcionesZona } from './modales/OpcionesZona'
import { PermisosZona } from './modales/PermisosZona'
import { PropiedadesDnssec } from './modales/PropiedadesDnssec'
import { VerDs } from './modales/VerDs'
import type { Aviso, Confirmacion } from './tipos'
import { Avisador } from '../../ui/Avisador'

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
  const [abierta, setAbierta] = useState<string | null>(null)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [confirmacion, setConfirmacion] = useState<Confirmacion | null>(null)
  const [modal, setModal] = useState<ModalId | null>(null)

  /** The zone the open modal acts on; it may not be the one on screen. */
  const [zonaModal, setZonaModal] = useState('')
  const [tipoModal, setTipoModal] = useState('')

  const [modoRegistro, setModoRegistro] = useState<'add' | 'update'>('add')
  const [zonaDeRegistros, setZonaDeRegistros] = useState<ZonaDeRegistros | null>(null)
  const [registros, setRegistros] = useState<Registro[]>([])
  const [registroOriginal, setRegistroOriginal] = useState<Registro | null>(null)

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

  function abrirModal(id: ModalId, zone: string, type = '') {
    setZonaModal(zone)
    setTipoModal(type)
    setModal(id)
  }

  /** After a mutating modal: refreshes whatever is in front. */
  function hecho(a: Aviso) {
    setAviso(a)
    if (abierta == null) releerLista()
    else releerZona()
  }

  return (
    <>
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {abierta == null ? (
        <ListaZonas
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onAviso={setAviso}
          onConfirmar={setConfirmacion}
          onAnadir={() => abrirModal('add', '')}
          onAbrir={(z) => {
            setAviso(null)
            setAbierta(z)
          }}
          onImportar={(z) => abrirModal('import', z)}
          onConvertir={(z, t) => abrirModal('convert', z, t)}
          onClonar={(z) => abrirModal('clone', z)}
          onPermisos={(z) => abrirModal('permissions', z)}
          onOpciones={(z) => abrirModal('options', z)}
          refresco={refrescoLista}
        />
      ) : (
        <RegistrosZona
          zone={abierta}
          token={token}
          node={node}
          canModify={canModify}
          canDelete={canDelete}
          onVolver={() => {
            setAbierta(null)
            releerLista()
          }}
          onAviso={setAviso}
          onConfirmar={setConfirmacion}
          onAnadirRegistro={(zona, regs) => {
            setModoRegistro('add')
            setZonaDeRegistros(zona)
            setRegistros(regs)
            setRegistroOriginal(null)
            abrirModal('record', abierta)
          }}
          onEditarRegistro={(zona, registro, regs) => {
            setModoRegistro('update')
            setZonaDeRegistros(zona)
            setRegistros(regs)
            setRegistroOriginal(registro)
            abrirModal('record', abierta)
          }}
          onImportar={(z) => abrirModal('import', z)}
          onConvertir={(z, t) => abrirModal('convert', z, t)}
          onClonar={(z) => abrirModal('clone', z)}
          onPermisos={(z) => abrirModal('permissions', z)}
          onOpciones={(z) => abrirModal('options', z)}
          onFirmar={(z) => abrirModal('sign', z)}
          onDesfirmar={(z) => abrirModal('unsign', z)}
          onVerDs={(z) => abrirModal('viewds', z)}
          onPropiedadesDnssec={(z) => abrirModal('dnssec', z)}
          refresco={refrescoZona}
          expiryTtlDelModal={expiryTtlDelModal}
        />
      )}

      <Confirmar
        abierto={confirmacion !== null}
        titulo={confirmacion?.titulo ?? ''}
        texto={confirmacion?.texto}
        etiqueta={confirmacion?.etiqueta ?? ''}
        variante={confirmacion?.peligro ? 'danger' : 'primary'}
        onCerrar={() => setConfirmacion(null)}
        onConfirmar={() => confirmacion?.accion()}
      />

      <AnadirZona
        abierto={modal === 'add'}
        token={token}
        node={node}
        useSoaSerialDateScheme={useSoaSerialDateScheme}
        dnssecValidation={dnssecValidation}
        onCerrar={() => setModal(null)}
        onCreada={(domain, a) => {
          // Upstream abre la zona recién creada, no vuelve a la lista.
          setAbierta(domain === '' ? '.' : domain)
          setAviso(a)
        }}
      />

      <ImportarZona
        zone={zonaModal}
        abierto={modal === 'import'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <ClonarZona
        zone={zonaModal}
        abierto={modal === 'clone'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <ConvertirZona
        zone={zonaModal}
        tipoOrigen={tipoModal}
        abierto={modal === 'convert'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <OpcionesZona
        zone={zonaModal}
        abierto={modal === 'options'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <PermisosZona
        zone={zonaModal}
        abierto={modal === 'permissions'}
        token={token}
        node={node}
        canModify={canModify}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <FirmarZona
        zone={zonaModal}
        abierto={modal === 'sign'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <DesfirmarZona
        zone={zonaModal}
        abierto={modal === 'unsign'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onHecho={hecho}
      />

      <VerDs
        zone={zonaModal}
        abierto={modal === 'viewds'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
      />

      <PropiedadesDnssec
        zone={zonaModal}
        abierto={modal === 'dnssec'}
        token={token}
        node={node}
        onCerrar={() => setModal(null)}
        onConfirmar={setConfirmacion}
        onCambio={releerZona}
      />

      <AnadirEditarRegistro
        abierto={modal === 'record'}
        modo={modoRegistro}
        zone={zonaModal}
        zona={zonaDeRegistros}
        registros={registros}
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

