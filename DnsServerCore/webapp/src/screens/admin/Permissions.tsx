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
import { anadirALaTabla, OPCION_BLANK, OPCION_NONE, serializarTabla, type Cell } from './tabla'
import { avisoDeFallo, MRow, adminStyles as styles, type Aviso } from './partes'
import { Th, useOrden, type Keys } from '../../ui/Table'
import { Select } from '../../ui/Select'
import { TablaEditable } from '../../ui/TablaEditable'
import { Avisador } from '../../ui/Avisador'

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
  onAviso: (a: Aviso) => void
}

export function Permissions({ token, cluster, onAviso }: Props) {
  const [secciones, setSecciones] = useState<SectionPermission[]>([])
  const [loading, setLoading] = useState(true)
  const [editar, setEditar] = useState<string | null>(null)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await listPermissions(token)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setSecciones([])
      onAviso(avisoDeFallo(outcome))
      return
    }
    setSecciones(outcome.data.response.permissions)
  }, [token, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  return (
    <>
      <SectionHeader
        section="Administration"
        titulo="Permissions"
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
              titulo={s.section}
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
                        <Brand active={p.canView} etiqueta={`${s.section} ${p.username} View`} />
                        <Brand active={p.canModify} etiqueta={`${s.section} ${p.username} Modify`} />
                        <Brand active={p.canDelete} etiqueta={`${s.section} ${p.username} Delete`} />
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
                        <Brand active={p.canView} etiqueta={`${s.section} ${p.name} View`} />
                        <Brand active={p.canModify} etiqueta={`${s.section} ${p.name} Modify`} />
                        <Brand active={p.canDelete} etiqueta={`${s.section} ${p.name} Delete`} />
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
        <EditarPermisos
          section={editar}
          token={token}
          nodoPrimario={primaryNodeName(cluster)}
          onCerrar={() => setEditar(null)}
          onSaved={(p) => {
            setSecciones((list) => list.map((x) => (x.section === p.section ? p : x)))
            onAviso({
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

function Brand({ active, etiqueta }: { active: boolean; etiqueta: string }) {
  return (
    <input
      type="checkbox"
      className={styles.pchk}
      aria-label={etiqueta}
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
function EditarPermisos({
  section,
  token,
  nodoPrimario,
  onCerrar,
  onSaved,
}: {
  section: string
  token: string | null
  nodoPrimario: string
  onCerrar: () => void
  onSaved: (p: SectionPermission) => void
}) {
  const [loading, setLoading] = useState(true)
  const [users, setUsuarios] = useState<readonly Row[]>([])
  const [groups, setGrupos] = useState<readonly Row[]>([])
  const [listaUsuarios, setListaUsuarios] = useState<string[]>([])
  const [listaGrupos, setListaGrupos] = useState<string[]>([])
  const [addUser, setAddUser] = useState(OPCION_BLANK)
  const [addGroup, setAddGroup] = useState(OPCION_BLANK)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [busy, setBusy] = useState(false)

  const cargar = useCallback(async () => {
    setLoading(true)
    const outcome = await getPermission(token, section)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    const d = outcome.data.response
    setUsuarios(
      d.userPermissions.map((p) => ({
        name: p.username,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setGrupos(
      d.groupPermissions.map((p) => ({
        name: p.name,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setListaUsuarios(d.users ?? [])
    setListaGrupos(d.groups ?? [])
    setAddUser(OPCION_BLANK)
    setAddGroup(OPCION_BLANK)
  }, [token, section])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function guardar() {
    const serie = (rows: readonly Row[]): Cell[][] =>
      rows.map((f) => [
        { tipo: 'text', value: f.name },
        { tipo: 'casilla', value: f.canView },
        { tipo: 'casilla', value: f.canModify },
        { tipo: 'casilla', value: f.canDelete },
      ])

    const u = serializarTabla(serie(users))
    if (!u.ok) {
      setAviso({ type: 'warning', title: u.fallo.title, text: u.fallo.text })
      return
    }
    const g = serializarTabla(serie(groups))
    if (!g.ok) {
      setAviso({ type: 'warning', title: g.fallo.title, text: g.fallo.text })
      return
    }

    setBusy(true)
    const outcome = await setPermissions(token, section, u.value, g.value, nodoPrimario)
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
      title={`Edit Permissions - ${section}`}
      /* The SAME dialog opened from a zone already went wide, and from here
         it went to 560: two widths for the same thing. It is not that it was
         cramped —the table shrinks and fits in all three sizes, measured— it is
         that its two entrances had to look the same. It goes with the title fix,
         which had also drifted between the two. */
      size="medium"
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
          <TablaPermisos
            titulo="User Permissions"
            header="Username"
            rows={users}
            onChange={setUsuarios}
          />
          <MRow label="Add User">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={addUser}
                onChange={(e) => {
                  setAddUser(e.target.value)
                  setUsuarios((f) => anadirALaTabla(f, e.target.value, nuevaFila))
                }}
              >
                <option value={OPCION_BLANK} />
                <option value={OPCION_NONE}>None</option>
                {listaUsuarios.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </MRow>

          <TablaPermisos
            titulo="Group Permissions"
            header="Group"
            rows={groups}
            onChange={setGrupos}
          />
          <MRow label="Add Group">
            {(id) => (
              <Select
                id={id}
                className={styles.select}
                value={addGroup}
                onChange={(e) => {
                  setAddGroup(e.target.value)
                  setGrupos((f) => anadirALaTabla(f, e.target.value, nuevaFila))
                }}
              >
                <option value={OPCION_BLANK} />
                <option value={OPCION_NONE}>None</option>
                {listaGrupos.map((n) => (
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

const nuevaFila = (name: string): Row => ({
  name,
  canView: false,
  canModify: false,
  canDelete: false,
})

/* `sortTable('tbodyEditPermissionsUser'|'Group', 0)`. */
const CLAVES_PERMISO: Keys<Row> = { name: (f) => f.name }

function TablaPermisos({
  titulo,
  header,
  rows,
  onChange,
}: {
  titulo: string
  header: string
  rows: readonly Row[]
  onChange: (f: readonly Row[]) => void
}) {
  const { rows: visibles, orden, alternar } = useOrden(CLAVES_PERMISO, rows as Row[])

  // The checkbox writes over the ORIGINAL list: the sorting only changes the
  // order things are drawn in, not the data's.
  function set(row: Row, parcial: Partial<Row>) {
    onChange(rows.map((f) => (f.name === row.name ? { ...f, ...parcial } : f)))
  }

  return (
    <>
      <p className={styles.sub}>{titulo}</p>
      {/* The editable one does not carry the data table's panel wrapper: it is
          another piece (`ui/TablaEditable.module.css`) and lives INSIDE a panel. */}
      <div>
        <TablaEditable
      className={styles.edit}
          header={
            <>
              <Th field="nombre" orden={orden} onOrdenar={alternar}>{header}</Th>
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
        </TablaEditable>
        {/* Upstream puts no text when the modal's table is empty; nor does it
            here, so as not to invent a literal that does not exist. */}
      </div>
    </>
  )
}
