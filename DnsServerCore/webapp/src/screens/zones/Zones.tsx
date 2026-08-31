import { useState } from 'react'
import type { Registro, ZonaDeRegistros } from '../../api/registros'
import { Alert } from '../../ui/Alert'
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
import styles from './Zones.module.css'

/*
La sección Zones entera: la lista, la vista de una zona y los diez modales.

Upstream son dos `div` que se enseñan y esconden (`divViewZones` y
`divEditZone`); aquí es un estado, `abierta`. El resto de la estructura es la
misma a propósito: mismos modales, mismos textos, mismos pasos.

**Los avisos viven aquí, no en cada pantalla.** En upstream `showAlert` sin
contenedor los pinta en la barra global, y así una acción lanzada desde un modal
que cierra el modal deja el aviso visible detrás. Con el aviso dentro de cada
pantalla ese caso se perdería.
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
  /** Heredan del ajuste global de Settings para el modal de alta. */
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

  /** La zona sobre la que actúa el modal abierto; puede no ser la que se ve. */
  const [zonaModal, setZonaModal] = useState('')
  const [tipoModal, setTipoModal] = useState('')

  const [modoRegistro, setModoRegistro] = useState<'add' | 'update'>('add')
  const [zonaDeRegistros, setZonaDeRegistros] = useState<ZonaDeRegistros | null>(null)
  const [registros, setRegistros] = useState<Registro[]>([])
  const [registroOriginal, setRegistroOriginal] = useState<Registro | null>(null)

  /*
  El TTL de expiración que queda en el modal de registro. Upstream lo lee de ese
  campo al DESHABILITAR un registro desde la fila (`updateRecordState`,
  zone.js:6236), así que el valor sobrevive al cierre del modal. Es un fallo
  suyo; se replica porque la regla es cero cambios de comportamiento.
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

  /** Tras un modal que muta: refresca lo que esté delante. */
  function hecho(a: Aviso) {
    setAviso(a)
    if (abierta == null) releerLista()
    else releerZona()
  }

  return (
    <>
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

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

