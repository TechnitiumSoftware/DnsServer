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
  type Lista,
  type ListaDominios,
  type NodoLista,
} from '../../api/zonelists'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Confirmar } from '../../ui/Confirmar'
import { Dialog } from '../../ui/Dialog'
import { Field, Input, LabeledTextarea } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { Arbol } from './Arbol'
import { Registros } from './Registros'
import styles from './Listas.module.css'
import { avisoDeFallo, type Aviso } from '../../lib/aviso'

/*
Cache, Allowed y Blocked. Una sola pantalla porque en upstream son tres copias
del mismo código (`refreshCachedZonesList`, `refreshAllowedZonesList` y
`refreshBlockedZonesList` son la misma función tres veces, other-zones.js).

Lo que de verdad cambia entre las tres son los TEXTOS —y no son intercambiables:
borrar en Allowed dice «Domain 'x' was deleted from Allowed Zone successfully.»
y borrar en Blocked dice «Blocked zone 'x' was deleted successfully.». Por eso
cada frase está escrita entera en su sitio en vez de componerse con plantillas:
una plantilla habría uniformado la asimetría y habría cambiado un texto.

Y lo que cambia en el COMPORTAMIENTO es cuándo se ve el botón Delete: en Cache
depende de estar fuera de la raíz (other-zones.js:143-152) y en Allowed y
Blocked de que el nodo tenga registros (líneas 319-327). Se replica tal cual.
*/


interface Confirmacion {
  titulo: string
  texto: string
  etiqueta: string
  accion: () => Promise<void>
}

const TITULO: Record<Lista, string> = { cache: 'Cache', allowed: 'Allowed', blocked: 'Blocked' }

/*
`importAllowedZones` / `importBlockedZones` (other-zones.js:589-661). El aviso de
lista vacía va DENTRO del modal, no en la página: upstream le pasa a `showAlert`
el `divImportAllowedZonesAlert` del propio modal.
*/
function Importar({
  lista,
  abierto,
  token,
  onCerrar,
  onHecho,
}: {
  lista: ListaDominios
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  const [texto, setTexto] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)
  const area = useRef<HTMLTextAreaElement>(null)

  const esAllowed = lista === 'allowed'
  const titulo = esAllowed ? 'Import Allowed Zones' : 'Import Blocked Zones'
  const etiqueta = esAllowed ? 'Allowed Zones' : 'Blocked Zones'
  const intro = esAllowed
    ? 'Enter domain names one below other to import into Allowed Zone:'
    : 'Enter domain names one below other to import into blocked zone:'

  // `resetImport*Modal`: al abrir, el modal empieza limpio y con el foco dentro.
  useEffect(() => {
    if (abierto) {
      setTexto('')
      setAviso(null)
      area.current?.focus()
    }
  }, [abierto])

  async function importar() {
    const zonas = limpiarLista(texto)

    if (zonas.length === 0 || zonas === ',') {
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

    setOcupado(true)
    const outcome = await importarDominios(lista, token, zonas)
    setOcupado(false)

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
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void importar()}>
            Import
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
      <p className={styles.parrafo}>{intro}</p>
      <LabeledTextarea
        label={etiqueta}
        ref={area}
        mono
        className={styles.area}
        spellCheck={false}
        value={texto}
        onChange={(e) => setTexto(e.target.value)}
      />
    </Dialog>
  )
}

export function Listas({ lista, token }: { lista: Lista; token: string | null }) {
  const [nodo, setNodo] = useState<NodoLista | null>(null)
  const [campo, setCampo] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [confirmacion, setConfirmacion] = useState<Confirmacion | null>(null)
  const [importAbierto, setImportAbierto] = useState(false)
  const [ocupado, setOcupado] = useState(false)
  const entrada = useRef<HTMLInputElement>(null)

  const esCache = lista === 'cache'
  const listaDominios = lista as ListaDominios

  const cargar = useCallback(
    async (domain: string, arriba?: boolean) => {
      const outcome = await listarNodo(lista, token, domain, arriba ? 'up' : undefined)
      if (outcome.kind === 'ok') {
        setNodo(outcome.data)
        return
      }
      // El manejador de errores de upstream deja la lista donde estaba y pinta
      // el errorMessage del servidor; aquí igual.
      setAviso(avisoDeFallo(outcome))
    },
    [lista, token],
  )

  useEffect(() => {
    void cargar('')
  }, [cargar])

  /** Envuelve una mutación: ejecuta, y en el fallo pinta el error del servidor. */
  async function mutar(
    fn: () => Promise<{ kind: string; message?: string }>,
    exito: Aviso,
    despues: () => Promise<void>,
  ) {
    setOcupado(true)
    const outcome = await fn()
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    await despues()
    setAviso(exito)
  }

  const domain = nodo?.domain ?? ''
  const tituloNodo = domain === '' ? '<ROOT>' : (nodo?.domainIdn ?? domain)
  const zones = nodo?.zones ?? []
  const records = nodo?.records ?? []

  // Cache: Delete cuelga del NODO. Allowed/Blocked: cuelga de que haya registros.
  const puedeBorrar = esCache ? domain !== '' : records.length > 0

  function navegar(d: string, arriba?: boolean) {
    void cargar(d, arriba)
  }

  // ---- acciones de Cache -------------------------------------------------

  function pedirFlushCache() {
    setConfirmacion({
      titulo: 'Flush Cache',
      texto: 'Are you sure to flush the DNS Server cache?',
      etiqueta: 'Flush Cache',
      accion: () =>
        mutar(
          () => vaciarCache(token),
          {
            type: 'success',
            title: 'Flushed!',
            text: 'DNS Server cache was flushed successfully.',
          },
          // Upstream deja la lista en `<ROOT>` y esconde el visor.
          () => cargar(''),
        ),
    })
  }

  function pedirBorrarNodoCache() {
    setConfirmacion({
      titulo: 'Delete Cached Zone',
      texto: `Are you sure you want to delete the cached zone '${tituloNodo}' and all its records?`,
      etiqueta: 'Delete',
      accion: () =>
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
    const dominio = campo

    // El aviso va ANTES de cualquier llamada, y deja el foco en el campo:
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
      entrada.current?.focus()
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
    setConfirmacion({
      titulo: esAllowed ? 'Delete Allowed Zone' : 'Delete Blocked Zone',
      texto: esAllowed
        ? `Are you sure you want to delete the allowed zone '${tituloNodo}'?`
        : `Are you sure you want to delete the blocked zone '${tituloNodo}'?`,
      etiqueta: 'Delete',
      accion: () =>
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
    setConfirmacion({
      titulo: esAllowed ? 'Flush Allowed Zone' : 'Flush Blocked Zone',
      texto: esAllowed
        ? 'Are you sure you want to flush the entire Allowed zone?'
        : 'Are you sure you want to flush the entire Blocked zone?',
      etiqueta: 'Flush',
      accion: () =>
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
    setOcupado(true)
    const r = await exportarDominios(listaDominios, token)
    setOcupado(false)
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
        titulo={TITULO[lista]}
        acciones={<>{esCache ? (
            <Button variant="danger" disabled={ocupado} onClick={pedirFlushCache}>
              Flush Cache
            </Button>
          ) : (
            <>
              <Button variant="primary" disabled={ocupado} onClick={() => void anadir()}>
                {listaDominios === 'allowed' ? 'Allow' : 'Block'}
              </Button>
              <Button disabled={ocupado} onClick={() => setImportAbierto(true)}>
                Import
              </Button>
              <Button disabled={ocupado} onClick={() => void exportar()}>
                Export
              </Button>
              <Button variant="danger" disabled={ocupado} onClick={pedirFlushLista}>
                Flush
              </Button>
            </>
          )}</>}
      />

      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

      <div className={styles.brow}>
        <div className={styles.tree}>
          <div className={styles.browse}>
            <div className={styles.browseRow}>
              {/* El campo se llama «Domain» y el botón «Browse». Upstream no pone
                  rótulo aquí —sólo el `placeholder`—, así que este es añadido
                  nuestro y puede llamarse como convenga; lo que no puede es
                  llamarse igual que el botón de al lado, que sí lleva el
                  literal de upstream. */}
              <Field label="Domain">
                {(id) => (
                  <Input
                    id={id}
                    ref={entrada}
                    mono
                    placeholder="example.com"
                    value={campo}
                    onChange={(e) => setCampo(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') navegar(campo)
                    }}
                  />
                )}
              </Field>
              {/* «Browse» y no «Go»: es el literal de upstream en las tres
                  pantallas de lista (Cache, Allowed y Blocked), y además dice
                  mejor lo que hace —te lleva a ese punto del árbol, no envía
                  nada—. */}
              <Button variant="primary" onClick={() => navegar(campo)}>
                Browse
              </Button>
            </div>
          </div>
          {/* El recuento vive en la barra de recuento, como el de registros: en
              la cabecera tenía el mismo aspecto que una píldora de estado. */}
          <div className={styles.count}>
            <span>{zones.length === 1 ? '1 zone' : `${zones.length} zones`}</span>
          </div>
          <Arbol
            domain={domain}
            domainIdn={nodo?.domainIdn}
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
                  disabled={ocupado}
                  onClick={esCache ? pedirBorrarNodoCache : pedirBorrarDominio}
                >
                  Delete
                </Button>
              )}
            </div>
          </div>

          {records.length > 0 ? (
            <Registros records={records} conDnssec={esCache} nodo={domain} />
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
        abierto={confirmacion !== null}
        titulo={confirmacion?.titulo ?? ''}
        texto={confirmacion?.texto}
        etiqueta={confirmacion?.etiqueta ?? ''}
        onCerrar={() => setConfirmacion(null)}
        onConfirmar={() => confirmacion?.accion()}
      />

      {!esCache && (
        <Importar
          lista={listaDominios}
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
  return <Listas lista="cache" token={token} />
}

export function Allowed({ token }: { token: string | null }) {
  return <Listas lista="allowed" token={token} />
}

export function Blocked({ token }: { token: string | null }) {
  return <Listas lista="blocked" token={token} />
}
