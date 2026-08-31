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
import { cleanList } from '../settings/model'
import { addToList, BLANK_OPTION, NONE_OPTION } from './table'
import {
  noticeFromFailure,
  Confirm,
  MRow,
  adminStyles as styles,
  type Notice,
} from './parts'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu } from '../../ui/Menu'
import { Notifier } from '../../ui/Notifier'

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
  onNotice: (a: Notice) => void
}

/* `sortTable('tbodyAdminGroups', 0..1)`. */
const KEYS: Keys<AdminGroup> = {
  name: (g) => g.name,
  description: (g) => g.description,
}

export function Groups({ token, onNotice }: Props) {
  const [groups, setGroups] = useState<AdminGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [add, setAdd] = useState(false)
  const [detail, setDetalle] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<AdminGroup | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await listGroups(token)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setGroups([])
      onNotice(noticeFromFailure(outcome))
      return
    }
    setGroups(outcome.data.response.groups)
  }, [token, onNotice])

  useEffect(() => {
    void load()
  }, [load])

  const { rows: visibleGroups, sort, toggle } = useOrden(KEYS, groups)

  async function remove(g: AdminGroup) {
    setPendingDelete(null)
    const outcome = await deleteGroup(token, g.name)
    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    setGroups((list) => list.filter((x) => x.name !== g.name))
    onNotice({ type: 'success', title: 'Group Deleted!', text: 'Group was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        title="Groups"
        actions={<><Button variant="primary" onClick={() => setAdd(true)}>
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
                <Th field="name" sort={sort} onSort={toggle}>Name</Th>
                <Th field="description" sort={sort} onSort={toggle}>Description</Th>
                <th className={tbl.actionsCell} />
              </>
            }
            isEmpty={visibleGroups.length === 0}
            emptyText="No Group Found"
            columns={3}
          >
            {visibleGroups.map((g) => (
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
                <td className={tbl.actionsCell}>
                  <div className={tbl.actions}>
                    <RowAction
                      icon="card"
                      name="View Details"
                      onClick={() => setDetalle(g.name)}
                    />
                    <Menu label={`Actions for ${g.name}`}>
                      {(close) => (
                        <button type="button" data-variant="danger" onClick={() => { close(); setPendingDelete(g) }}>
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

      <Confirm
        open={pendingDelete !== null}
        title="Delete Group"
        text={`Are you sure you want to delete the group [${pendingDelete?.name ?? ''}] ?`}
        label="Delete"
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && void remove(pendingDelete)}
      />

      <AddGroup
        open={add}
        token={token}
        onClose={() => setAdd(false)}
        onAnadido={(g) => {
          setGroups((list) => [g, ...list])
          onNotice({ type: 'success', title: 'Group Added!', text: 'Group was added successfully.' })
        }}
      />

      {detail != null && (
        <GroupDetail
          name={detail}
          token={token}
          onClose={() => setDetalle(null)}
          onSaved={(g) => {
            setGroups((list) => list.map((x) => (x.name === detail ? g : x)))
            onNotice({
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
function AddGroup({
  open,
  token,
  onClose,
  onAnadido,
}: {
  open: boolean
  token: string | null
  onClose: () => void
  onAnadido: (g: AdminGroup) => void
}) {
  const [name, setNombre] = useState('')
  const [description, setDescription] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setNombre('')
    setDescription('')
  }, [open])

  async function add() {
    if (name === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter a name to add group.' })
      return
    }

    setBusy(true)
    const outcome = await createGroup(token, name, description)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onAnadido(outcome.data.response)
    onClose()
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Add Group"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void add()}>
            Add
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
function GroupDetail({
  name,
  token,
  onClose,
  onSaved,
}: {
  name: string
  token: string | null
  onClose: () => void
  onSaved: (g: AdminGroup) => void
}) {
  const [loading, setLoading] = useState(true)
  const [newName, setNuevoNombre] = useState('')
  const [description, setDescription] = useState('')
  const [miembros, setMiembros] = useState('')
  const [users, setUsers] = useState<string[]>([])
  const [addUser, setAddUser] = useState(BLANK_OPTION)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await getGroup(token, name)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    const d = outcome.data.response
    setNuevoNombre(d.name)
    setDescription(d.description)
    setMiembros(d.members.map((m) => `${m}\n`).join(''))
    setUsers(d.users ?? [])
    setAddUser(BLANK_OPTION)
  }, [token, name])

  useEffect(() => {
    void load()
  }, [load])

  async function save() {
    setBusy(true)
    const outcome = await setGroup(
      token,
      name,
      description,
      cleanList(miembros),
      newName !== name ? newName : undefined,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onSaved(outcome.data.response)
    onClose()
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Group Details"
      actions={
        <>
          <Button variant="primary" disabled={busy || loading} onClick={() => void save()}>
            Save
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
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
                value={newName}
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
                  setMiembros((t) => addToList(t, e.target.value))
                }}
              >
                <option value={BLANK_OPTION} />
                <option value={NONE_OPTION}>None</option>
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
