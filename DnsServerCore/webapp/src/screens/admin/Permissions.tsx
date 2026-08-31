import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import { Panel } from '../../ui/Panel'
import {
  getPermission,
  listPermissions,
  setPermissions,
  type SectionPermission,
} from '../../api/admin'
import { primaryNodeName, type ClusterState } from '../../api/admin-cluster'
import { addToTable, BLANK_OPTION, NONE_OPTION, serializeTable, type Cell } from './tabla'
import { noticeFromFailure, MRow, adminStyles as styles, type Notice } from './partes'
import { Th, useOrden, type Keys } from '../../ui/Table'
import { Select } from '../../ui/Select'
import { EditableTable } from '../../ui/TablaEditable'
import { Notifier } from '../../ui/Avisador'

/*
`refreshAdminPermissions`, `showEditSectionPermissionsModal` and
`saveSectionPermissions` (auth.js:1938-2150).

Three things that govern this screen:

  · The list's table is READ-ONLY: permissions are edited in the modal. Here the
    checkboxes are drawn disabled, which is the equivalent of upstream's
    `glyphicon-ok` while still resembling the modal's table.
  · The group list the modal offers INCLUDES `Everyone`, and `groups/list`'s does
    not. They are two different lists from the server and cannot be swapped
    (checked live against a v15.4).
  · `permissions/set` travels with `node` = the name of the cluster's PRIMARY
    node, not the node being looked at; an empty string when there is no cluster.
    And it asks for `Administration.canDelete`, not `canModify`
    (WebServiceAuthApi.cs:1533).
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onNotice: (a: Notice) => void
}

export function Permissions({ token, cluster, onNotice }: Props) {
  const [secciones, setSecciones] = useState<SectionPermission[]>([])
  const [loading, setLoading] = useState(true)
  const [editar, setEditar] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await listPermissions(token)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setSecciones([])
      onNotice(noticeFromFailure(outcome))
      return
    }
    setSecciones(outcome.data.response.permissions)
  }, [token, onNotice])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <>
      <SectionHeader
        section="Administration"
        title="Permissions"
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          {/* The section's name is the panel's title, not a link: it was an
              orange button and did the same thing as the "Edit Permissions" next
              to it. Upstream does not link it either (`auth.js:1975`). */}
          {secciones.map((s) => (
            <Panel
              key={s.section}
              className={styles.perm}
              title={s.section}
              actions={
                <Button size="sm" onClick={() => setEditar(s.section)}>
                  Edit Permissions
                </Button>
              }
            >
              <div className={styles.permCols}>
                <div className={styles.permCol}>
                  <div className={styles.permTitle}>User Permissions</div>
                  <div className={styles.prow}>
                    <span className={styles.phd} style={{ textAlign: 'left' }}>
                      Username
                    </span>
                    <span className={styles.phd}>View</span>
                    <span className={styles.phd}>Modify</span>
                    <span className={styles.phd}>Delete</span>
                  </div>
                  {s.userPermissions.length === 0 ? (
                    <div className={styles.prow}>
                      <span className={styles.pnone}>No user permissions</span>
                    </div>
                  ) : (
                    s.userPermissions.map((p) => (
                      <div className={styles.prow} key={p.username}>
                        <span className={styles.who}>{p.username}</span>
                        <Brand active={p.canView} label={`${s.section} ${p.username} View`} />
                        <Brand active={p.canModify} label={`${s.section} ${p.username} Modify`} />
                        <Brand active={p.canDelete} label={`${s.section} ${p.username} Delete`} />
                      </div>
                    ))
                  )}
                </div>

                <div className={styles.permCol}>
                  <div className={styles.permTitle}>Group Permissions</div>
                  <div className={styles.prow}>
                    <span className={styles.phd} style={{ textAlign: 'left' }}>
                      Group
                    </span>
                    <span className={styles.phd}>View</span>
                    <span className={styles.phd}>Modify</span>
                    <span className={styles.phd}>Delete</span>
                  </div>
                  {s.groupPermissions.length === 0 ? (
                    <div className={styles.prow}>
                      <span className={styles.pnone}>No group permissions</span>
                    </div>
                  ) : (
                    s.groupPermissions.map((p) => (
                      <div className={styles.prow} key={p.name}>
                        <span className={styles.who}>{p.name}</span>
                        <Brand active={p.canView} label={`${s.section} ${p.name} View`} />
                        <Brand active={p.canModify} label={`${s.section} ${p.name} Modify`} />
                        <Brand active={p.canDelete} label={`${s.section} ${p.name} Delete`} />
                      </div>
                    ))
                  )}
                </div>
              </div>
            </Panel>
          ))}
          <div className={styles.count}>
            <span>{`Total Sections: ${secciones.length}`}</span>
          </div>
        </>
      )}

      {editar != null && (
        <EditPermissions
          section={editar}
          token={token}
          primaryNode={primaryNodeName(cluster)}
          onClose={() => setEditar(null)}
          onSaved={(p) => {
            setSecciones((list) => list.map((x) => (x.section === p.section ? p : x)))
            onNotice({
              type: 'success',
              title: 'Permissions Saved!',
              text: 'Section permissions were saved successfully.',
            })
          }}
        />
      )}
    </>
  )
}

function Brand({ active, label }: { active: boolean; label: string }) {
  return (
    <input
      type="checkbox"
      className={styles.pchk}
      aria-label={label}
      checked={active}
      disabled
      readOnly
    />
  )
}

interface Row {
  name: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

/** `showEditSectionPermissionsModal` / `saveSectionPermissions`. */
function EditPermissions({
  section,
  token,
  primaryNode,
  onClose,
  onSaved,
}: {
  section: string
  token: string | null
  primaryNode: string
  onClose: () => void
  onSaved: (p: SectionPermission) => void
}) {
  const [loading, setLoading] = useState(true)
  const [users, setUsers] = useState<readonly Row[]>([])
  const [groups, setGroups] = useState<readonly Row[]>([])
  const [userList, setUserList] = useState<string[]>([])
  const [groupList, setGroupList] = useState<string[]>([])
  const [addUser, setAddUser] = useState(BLANK_OPTION)
  const [addGroup, setAddGroup] = useState(BLANK_OPTION)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await getPermission(token, section)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    const d = outcome.data.response
    setUsers(
      d.userPermissions.map((p) => ({
        name: p.username,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setGroups(
      d.groupPermissions.map((p) => ({
        name: p.name,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setUserList(d.users ?? [])
    setGroupList(d.groups ?? [])
    setAddUser(BLANK_OPTION)
    setAddGroup(BLANK_OPTION)
  }, [token, section])

  useEffect(() => {
    void load()
  }, [load])

  async function save() {
    const serie = (rows: readonly Row[]): Cell[][] =>
      rows.map((f) => [
        { type: 'text', value: f.name },
        { type: 'casilla', value: f.canView },
        { type: 'casilla', value: f.canModify },
        { type: 'casilla', value: f.canDelete },
      ])

    const u = serializeTable(serie(users))
    if (!u.ok) {
      setNotice({ type: 'warning', title: u.failure.title, text: u.failure.text })
      return
    }
    const g = serializeTable(serie(groups))
    if (!g.ok) {
      setNotice({ type: 'warning', title: g.failure.title, text: g.failure.text })
      return
    }

    setBusy(true)
    const outcome = await setPermissions(token, section, u.value, g.value, primaryNode)
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
      title={`Edit Permissions - ${section}`}
      /* The SAME dialog opened from a zone already went wide, and from here
         it went to 560: two widths for the same thing. It is not that it was
         cramped —the table shrinks and fits in all three sizes, measured— it is
         that its two entrances had to look the same. It goes with the title fix,
         which had also drifted between the two. */
      size="medium"
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
          <PermissionsTable
            title="User Permissions"
            header="Username"
            rows={users}
            onChange={setUsers}
          />
          <MRow label="Add User">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={addUser}
                onChange={(e) => {
                  setAddUser(e.target.value)
                  setUsers((f) => addToTable(f, e.target.value, blankRow))
                }}
              >
                <option value={BLANK_OPTION} />
                <option value={NONE_OPTION}>None</option>
                {userList.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </MRow>

          <PermissionsTable
            title="Group Permissions"
            header="Group"
            rows={groups}
            onChange={setGroups}
          />
          <MRow label="Add Group">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={addGroup}
                onChange={(e) => {
                  setAddGroup(e.target.value)
                  setGroups((f) => addToTable(f, e.target.value, blankRow))
                }}
              >
                <option value={BLANK_OPTION} />
                <option value={NONE_OPTION}>None</option>
                {groupList.map((n) => (
                  <option key={n} value={n}>
                    {n}
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

const blankRow = (name: string): Row => ({
  name,
  canView: false,
  canModify: false,
  canDelete: false,
})

/* `sortTable('tbodyEditPermissionsUser'|'Group', 0)`. */
const PERMISSION_KEYS: Keys<Row> = { name: (f) => f.name }

function PermissionsTable({
  title,
  header,
  rows,
  onChange,
}: {
  title: string
  header: string
  rows: readonly Row[]
  onChange: (f: readonly Row[]) => void
}) {
  const { rows: visibles, sort, toggle } = useOrden(PERMISSION_KEYS, rows as Row[])

  // The checkbox writes over the ORIGINAL list: the sorting only changes the
  // order things are drawn in, not the data's.
  function set(row: Row, parcial: Partial<Row>) {
    onChange(rows.map((f) => (f.name === row.name ? { ...f, ...parcial } : f)))
  }

  return (
    <>
      <p className={styles.sub}>{title}</p>
      {/* The editable one does not carry the data table's panel wrapper: it is
          another piece (`ui/TablaEditable.module.css`) and lives INSIDE a panel. */}
      <div>
        <EditableTable
      className={styles.edit}
          header={
            <>
              <Th field="nombre" sort={sort} onSort={toggle}>{header}</Th>
              <th>View</th>
              <th>Modify</th>
              <th>Delete</th>
              <th className={styles.tdel} />
            </>
          }
        >
          {visibles.map((f) => (
            <tr key={f.name}>
              <td className={styles.who}>{f.name}</td>
              <td>
                <input
                  type="checkbox"
                  className={styles.chkPerm}
                  aria-label={`${f.name} View`}
                  checked={f.canView}
                  onChange={(e) => set(f, { canView: e.target.checked })}
                />
              </td>
              <td>
                <input
                  type="checkbox"
                  className={styles.chkPerm}
                  aria-label={`${f.name} Modify`}
                  checked={f.canModify}
                  onChange={(e) => set(f, { canModify: e.target.checked })}
                />
              </td>
              <td>
                <input
                  type="checkbox"
                  className={styles.chkPerm}
                  aria-label={`${f.name} Delete`}
                  checked={f.canDelete}
                  onChange={(e) => set(f, { canDelete: e.target.checked })}
                />
              </td>
              <td className={styles.tdel}>
                <Button onClick={() => onChange(rows.filter((x) => x.name !== f.name))}>Remove</Button>
              </td>
            </tr>
          ))}
        </EditableTable>
        {/* Upstream puts no text when the modal's table is empty; nor does it
            here, so as not to invent a literal that does not exist. */}
      </div>
    </>
  )
}
