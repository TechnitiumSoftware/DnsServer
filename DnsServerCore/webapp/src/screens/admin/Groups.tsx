import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input, Select, Textarea } from '../../ui/Field'
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
import { AccionFila, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { Avisador } from '../../ui/Avisador'

/*
`refreshAdminGroups`, `addGroup`, `showGroupDetailsModal`, `saveGroupDetails` and
`deleteGroup` (auth.js:1699-1937).

One table detail that is not decoration: the description is drawn with its
newlines turned into `<br />` (auth.js:1731), because the field is a textarea of
up to 255 characters and can carry them.

And one about saving: `newGroup` only travels if the name CHANGED. Always sending
it would make the server try to rename the group to itself.
*/

interface Props {
  token: string | null
  onAviso: (a: Aviso) => void
}

/* `sortTable('tbodyAdminGroups', 0..1)`. */
const KEYS: Keys<AdminGroup> = {
  name: (g) => g.name,
  description: (g) => g.description,
}

export function Groups({ token, onAviso }: Props) {
  const [groups, setGrupos] = useState<AdminGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [anadir, setAnadir] = useState(false)
  const [detalle, setDetalle] = useState<string | null>(null)
  const [porBorrar, setPorBorrar] = useState<AdminGroup | null>(null)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await listGroups(token)
    setLoading(false)

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

  const { rows: gruposVisibles, orden, alternar } = useOrden(KEYS, groups)

  async function borrar(g: AdminGroup) {
    setPorBorrar(null)
    const outcome = await deleteGroup(token, g.name)
    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    setGrupos((list) => list.filter((x) => x.name !== g.name))
    onAviso({ type: 'success', title: 'Group Deleted!', text: 'Group was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        titulo="Groups"
        actions={<><Button variant="primary" onClick={() => setAnadir(true)}>
            Add Group
          </Button></>}
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          <Table
            header={
              <>
                <Th field="name" orden={orden} onOrdenar={alternar}>Name</Th>
                <Th field="description" orden={orden} onOrdenar={alternar}>Description</Th>
                <th className={tbl.celdaAcciones} />
              </>
            }
            isEmpty={gruposVisibles.length === 0}
            emptyText="No Group Found"
            columnas={3}
          >
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
                  {g.description.split('\n').map((line, i) => (
                    // eslint-disable-next-line react/no-array-index-key
                    <div key={i}>{line}</div>
                  ))}
                </td>
                <td className={tbl.celdaAcciones}>
                  <div className={tbl.actions}>
                    <AccionFila
                      icono="ficha"
                      name="View Details"
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
          </Table>
          <div className={styles.count}>
            <span>{`Total Groups: ${groups.length}`}</span>
          </div>
        </>
      )}

      <Confirmar
        abierto={porBorrar !== null}
        titulo="Delete Group"
        text={`Are you sure you want to delete the group [${porBorrar?.name ?? ''}] ?`}
        etiqueta="Delete"
        onCerrar={() => setPorBorrar(null)}
        onConfirmar={() => porBorrar && void borrar(porBorrar)}
      />

      <AnadirGrupo
        abierto={anadir}
        token={token}
        onCerrar={() => setAnadir(false)}
        onAnadido={(g) => {
          setGrupos((list) => [g, ...list])
          onAviso({ type: 'success', title: 'Group Added!', text: 'Group was added successfully.' })
        }}
      />

      {detalle != null && (
        <DetalleGrupo
          name={detalle}
          token={token}
          onCerrar={() => setDetalle(null)}
          onSaved={(g) => {
            setGrupos((list) => list.map((x) => (x.name === detalle ? g : x)))
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

/** `addGroup` (auth.js:1755). Only one validation: the name. */
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
  const [name, setNombre] = useState('')
  const [description, setDescription] = useState('')
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setNombre('')
    setDescription('')
  }, [abierto])

  async function anadir() {
    if (name === '') {
      setAviso({ type: 'warning', title: 'Missing!', text: 'Please enter a name to add group.' })
      return
    }

    setBusy(true)
    const outcome = await createGroup(token, name, description)
    setBusy(false)

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
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void anadir()}>
            Add
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      <MRow label="Name">
        {(id) => (
          <Input
            id={id}
            placeholder="group name"
            maxLength={255}
            value={name}
            onChange={(e) => setNombre(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Description">
        {(id) => (
          <Textarea
            mono
            id={id}
            className={styles.area}
            rows={5}
            maxLength={255}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/** `showGroupDetailsModal` / `saveGroupDetails` (auth.js:1798-1902). */
function DetalleGrupo({
  name,
  token,
  onCerrar,
  onSaved,
}: {
  name: string
  token: string | null
  onCerrar: () => void
  onSaved: (g: AdminGroup) => void
}) {
  const [loading, setLoading] = useState(true)
  const [nuevoNombre, setNuevoNombre] = useState('')
  const [description, setDescription] = useState('')
  const [miembros, setMiembros] = useState('')
  const [users, setUsuarios] = useState<string[]>([])
  const [addUser, setAddUser] = useState(OPCION_BLANK)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await getGroup(token, name)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    const d = outcome.data.response
    setNuevoNombre(d.name)
    setDescription(d.description)
    setMiembros(d.members.map((m) => `${m}\n`).join(''))
    setUsuarios(d.users ?? [])
    setAddUser(OPCION_BLANK)
  }, [token, name])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function guardar() {
    setBusy(true)
    const outcome = await setGroup(
      token,
      name,
      description,
      limpiarLista(miembros),
      nuevoNombre !== name ? nuevoNombre : undefined,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    onSaved(outcome.data.response)
    onCerrar()
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onCerrar()}
      title="Group Details"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading} onClick={() => void guardar()}>
            Save
          </Button>
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />
      {loading ? (
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
              <Textarea
                mono
                id={id}
                className={styles.area}
                rows={3}
                maxLength={255}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            )}
          </MRow>
          <MRow label="Members">
            {(id) => (
              <Textarea
                mono
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
                {users.map((u) => (
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
