import { useCallback, useEffect, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import {
  createGroup,
  deleteGroup,
  getGroup,
  listGroups,
  setGroup,
  type AdminGroup,
} from '../../api/admin'
import { limpiarLista } from '../settings/model'
import { anadirALaLista, OPCION_BLANK, OPCION_NONE } from './tabla'
import {
  avisoDeFallo,
  Confirmar,
  MRow,
  adminStyles as styles,
  type Aviso,
} from './partes'
import tbl from '../../ui/Table.module.css'
import { AccionFila, Th, useOrden, type Claves } from '../../ui/Table'
import { Menu } from '../../ui/Menu'

/*
`refreshAdminGroups`, `addGroup`, `showGroupDetailsModal`, `saveGroupDetails` y
`deleteGroup` (auth.js:1699-1937).

Un detalle de la tabla que no es adorno: la descripción se pinta con los saltos
de línea convertidos en `<br />` (auth.js:1731), porque el campo es un textarea
de hasta 255 caracteres y puede traerlos.

Y uno del guardado: `newGroup` sólo viaja si el nombre CAMBIÓ. Mandarlo siempre
haría que el servidor intentase renombrar el grupo a sí mismo.
*/

interface Props {
  token: string | null
  onAviso: (a: Aviso) => void
}

/* `sortTable('tbodyAdminGroups', 0..1)`. */
const CLAVES: Claves<AdminGroup> = {
  name: (g) => g.name,
  description: (g) => g.description,
}

export function Groups({ token, onAviso }: Props) {
  const [grupos, setGrupos] = useState<AdminGroup[]>([])
  const [cargando, setCargando] = useState(true)
  const [anadir, setAnadir] = useState(false)
  const [detalle, setDetalle] = useState<string | null>(null)
  const [porBorrar, setPorBorrar] = useState<AdminGroup | null>(null)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await listGroups(token)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setGrupos([])
      onAviso(avisoDeFallo(outcome))
      return
    }
    setGrupos(outcome.data.response.groups)
  }, [token, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  const { filas: gruposVisibles, orden, alternar } = useOrden(CLAVES, grupos)

  async function borrar(g: AdminGroup) {
    setPorBorrar(null)
    const outcome = await deleteGroup(token, g.name)
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setGrupos((lista) => lista.filter((x) => x.name !== g.name))
    onAviso({ type: 'success', title: 'Group Deleted!', text: 'Group was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        seccion="Administration"
        titulo="Groups"
        acciones={<><Button variant="primary" onClick={() => setAnadir(true)}>
            Add Group
          </Button></>}
      />

      {cargando ? (
        <Loading />
      ) : (
        <>
          <div className={tbl.wrap}>
            <table className={tbl.tabla}>
              <thead>
                <tr>
                  <Th campo="name" orden={orden} onOrdenar={alternar}>Name</Th>
                  <Th campo="description" orden={orden} onOrdenar={alternar}>Description</Th>
                  <th className={tbl.celdaAcciones} />
                </tr>
              </thead>
              <tbody>
                {gruposVisibles.length === 0 && (
                  <tr>
                    <td colSpan={3} className={tbl.sinFilas}>
                      No Group Found
                    </td>
                  </tr>
                )}
                {gruposVisibles.map((g) => (
                  <tr key={g.name}>
                    <td>
                      <button
                        type="button"
                        className={styles.link}
                        onClick={() => setDetalle(g.name)}
                      >
                        {g.name}
                      </button>
                    </td>
                    <td>
                      {g.description.split('\n').map((linea, i) => (
                        // eslint-disable-next-line react/no-array-index-key
                        <div key={i}>{linea}</div>
                      ))}
                    </td>
                    <td className={tbl.celdaAcciones}>
                      <div className={tbl.acciones}>
                        <AccionFila
                          icono="ficha"
                          nombre="View Details"
                          onClick={() => setDetalle(g.name)}
                        />
                        <Menu etiqueta={`Actions for ${g.name}`}>
                          {(cerrar) => (
                            <button type="button" data-variant="danger" onClick={() => { cerrar(); setPorBorrar(g) }}>
                              Delete Group
                            </button>
                          )}
                        </Menu>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.count}>
            <span>{`Total Groups: ${grupos.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Group"
        texto={`Are you sure you want to delete the group [${porBorrar?.name ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void borrar(porBorrar)}
      />

      <AnadirGrupo
        abierto={anadir}
        token={token}
        onCerrar={() => setAnadir(false)}
        onAnadido={(g) => {
          setGrupos((lista) => [g, ...lista])
          onAviso({ type: 'success', title: 'Group Added!', text: 'Group was added successfully.' })
        }}
      />

      {detalle != null && (
        <DetalleGrupo
          nombre={detalle}
          token={token}
          onCerrar={() => setDetalle(null)}
          onGuardado={(g) => {
            setGrupos((lista) => lista.map((x) => (x.name === detalle ? g : x)))
            onAviso({
              type: 'success',
              title: 'Group Saved!',
              text: 'Group details were saved successfully.',
            })
          }}
        />
      )}
    </>
  )
}

/** `addGroup` (auth.js:1755). Sólo una validación: el nombre. */
function AnadirGrupo({
  abierto,
  token,
  onCerrar,
  onAnadido,
}: {
  abierto: boolean
  token: string | null
  onCerrar: () => void
  onAnadido: (g: AdminGroup) => void
}) {
  const [nombre, setNombre] = useState('')
  const [descripcion, setDescripcion] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setNombre('')
    setDescripcion('')
  }, [abierto])

  async function anadir() {
    if (nombre === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a name to add group.' })
      return
    }

    setOcupado(true)
    const outcome = await createGroup(token, nombre, descripcion)
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onAnadido(outcome.data.response)
    onCerrar()
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      title="Add Group"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado} onClick={() => void anadir()}>
            Add
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      <MRow label="Name">
        {(id) => (
          <Input
            id={id}
            placeholder="group name"
            maxLength={255}
            value={nombre}
            onChange={(e) => setNombre(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Description">
        {(id) => (
          <textarea
            id={id}
            className={styles.area}
            rows={5}
            maxLength={255}
            value={descripcion}
            onChange={(e) => setDescripcion(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/** `showGroupDetailsModal` / `saveGroupDetails` (auth.js:1798-1902). */
function DetalleGrupo({
  nombre,
  token,
  onCerrar,
  onGuardado,
}: {
  nombre: string
  token: string | null
  onCerrar: () => void
  onGuardado: (g: AdminGroup) => void
}) {
  const [cargando, setCargando] = useState(true)
  const [nuevoNombre, setNuevoNombre] = useState('')
  const [descripcion, setDescripcion] = useState('')
  const [miembros, setMiembros] = useState('')
  const [usuarios, setUsuarios] = useState<string[]>([])
  const [addUser, setAddUser] = useState(OPCION_BLANK)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await getGroup(token, nombre)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    const d = outcome.data.response
    setNuevoNombre(d.name)
    setDescripcion(d.description)
    setMiembros(d.members.map((m) => `${m}\n`).join(''))
    setUsuarios(d.users ?? [])
    setAddUser(OPCION_BLANK)
  }, [token, nombre])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function guardar() {
    setOcupado(true)
    const outcome = await setGroup(
      token,
      nombre,
      descripcion,
      limpiarLista(miembros),
      nuevoNombre !== nombre ? nuevoNombre : undefined,
    )
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onGuardado(outcome.data.response)
    onCerrar()
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Group Details"
      acciones={
        <>
          <Button variant="primary" disabled={ocupado || cargando} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      {aviso && (
        <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
          {aviso.text}
        </Alert>
      )}
      {cargando ? (
        <Loading />
      ) : (
        <>
          <MRow label="Name">
            {(id) => (
              <Input
                id={id}
                placeholder="group name"
                maxLength={255}
                value={nuevoNombre}
                onChange={(e) => setNuevoNombre(e.target.value)}
              />
            )}
          </MRow>
          <MRow label="Description">
            {(id) => (
              <textarea
                id={id}
                className={styles.area}
                rows={3}
                maxLength={255}
                value={descripcion}
                onChange={(e) => setDescripcion(e.target.value)}
              />
            )}
          </MRow>
          <MRow label="Members">
            {(id) => (
              <textarea
                id={id}
                className={styles.area}
                rows={7}
                value={miembros}
                onChange={(e) => setMiembros(e.target.value)}
              />
            )}
          </MRow>
          <MRow label="Add User">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={addUser}
                onChange={(e) => {
                  setAddUser(e.target.value)
                  setMiembros((t) => anadirALaLista(t, e.target.value))
                }}
              >
                <option value={OPCION_BLANK} />
                <option value={OPCION_NONE}>None</option>
                {usuarios.map((u) => (
                  <option key={u} value={u}>
                    {u}
                  </option>
                ))}
              </Select>
            )}
          </MRow>
        </>
      )}
    </Dialog>
  )
}
