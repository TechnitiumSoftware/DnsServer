import { useCallback, useEffect, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import {
  getPermission,
  listPermissions,
  setPermissions,
  type SectionPermission,
} from '../../api/admin'
import { primaryNodeName, type ClusterState } from '../../api/admin-cluster'
import { anadirALaTabla, OPCION_BLANK, OPCION_NONE, serializarTabla, type Celda } from './tabla'
import { avisoDeFallo, MRow, adminStyles as styles, type Aviso } from './partes'
import tbl from '../../ui/Table.module.css'
import { Th, useOrden, type Claves } from '../../ui/Table'

/*
`refreshAdminPermissions`, `showEditSectionPermissionsModal` y
`saveSectionPermissions` (auth.js:1938-2150).

Tres cosas que gobiernan esta pantalla:

  · La tabla de la lista es de SÓLO LECTURA: los permisos se editan en el modal.
    Aquí las casillas se pintan deshabilitadas, que es el equivalente del
    `glyphicon-ok` de upstream sin dejar de parecerse a la tabla del modal.
  · La lista de grupos que ofrece el modal INCLUYE `Everyone`, y la de
    `groups/list` no. Son dos listas distintas del servidor y no se pueden
    intercambiar (comprobado en vivo contra una v15.4).
  · `permissions/set` viaja con `node` = nombre del nodo PRIMARIO del cluster, no
    con el nodo que se esté mirando; cadena vacía cuando no hay cluster. Y pide
    permiso `Administration.canDelete`, no `canModify` (WebServiceAuthApi.cs:1533).
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onAviso: (a: Aviso) => void
}

export function Permissions({ token, cluster, onAviso }: Props) {
  const [secciones, setSecciones] = useState<SectionPermission[]>([])
  const [cargando, setCargando] = useState(true)
  const [editar, setEditar] = useState<string | null>(null)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await listPermissions(token)
    setCargando(false)

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
        seccion="Administration"
        titulo="Permissions"
      />

      {cargando ? (
        <Loading />
      ) : (
        <>
          {secciones.map((s) => (
            <div className={styles.perm} key={s.section}>
              <h4 className={styles.permHead}>
                <button type="button" className={styles.link} onClick={() => setEditar(s.section)}>
                  {s.section}
                </button>
                <Button size="sm" onClick={() => setEditar(s.section)}>
                  Edit Permissions
                </Button>
              </h4>
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
                        <Marca activo={p.canView} etiqueta={`${s.section} ${p.username} View`} />
                        <Marca activo={p.canModify} etiqueta={`${s.section} ${p.username} Modify`} />
                        <Marca activo={p.canDelete} etiqueta={`${s.section} ${p.username} Delete`} />
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
                        <Marca activo={p.canView} etiqueta={`${s.section} ${p.name} View`} />
                        <Marca activo={p.canModify} etiqueta={`${s.section} ${p.name} Modify`} />
                        <Marca activo={p.canDelete} etiqueta={`${s.section} ${p.name} Delete`} />
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ))}
          <div className={styles.count}>
            <span>{`Total Sections: ${secciones.length}`}</span>
          </div>
        </>
      )}

      {editar != null && (
        <EditarPermisos
          seccion={editar}
          token={token}
          nodoPrimario={primaryNodeName(cluster)}
          onCerrar={() => setEditar(null)}
          onGuardado={(p) => {
            setSecciones((lista) => lista.map((x) => (x.section === p.section ? p : x)))
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

function Marca({ activo, etiqueta }: { activo: boolean; etiqueta: string }) {
  return (
    <input
      type="checkbox"
      className={styles.pchk}
      aria-label={etiqueta}
      checked={activo}
      disabled
      readOnly
    />
  )
}

interface Fila {
  nombre: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

/** `showEditSectionPermissionsModal` / `saveSectionPermissions`. */
function EditarPermisos({
  seccion,
  token,
  nodoPrimario,
  onCerrar,
  onGuardado,
}: {
  seccion: string
  token: string | null
  nodoPrimario: string
  onCerrar: () => void
  onGuardado: (p: SectionPermission) => void
}) {
  const [cargando, setCargando] = useState(true)
  const [usuarios, setUsuarios] = useState<readonly Fila[]>([])
  const [grupos, setGrupos] = useState<readonly Fila[]>([])
  const [listaUsuarios, setListaUsuarios] = useState<string[]>([])
  const [listaGrupos, setListaGrupos] = useState<string[]>([])
  const [addUser, setAddUser] = useState(OPCION_BLANK)
  const [addGroup, setAddGroup] = useState(OPCION_BLANK)
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [ocupado, setOcupado] = useState(false)

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await getPermission(token, seccion)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }
    const d = outcome.data.response
    setUsuarios(
      d.userPermissions.map((p) => ({
        nombre: p.username,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setGrupos(
      d.groupPermissions.map((p) => ({
        nombre: p.name,
        canView: p.canView,
        canModify: p.canModify,
        canDelete: p.canDelete,
      })),
    )
    setListaUsuarios(d.users ?? [])
    setListaGrupos(d.groups ?? [])
    setAddUser(OPCION_BLANK)
    setAddGroup(OPCION_BLANK)
  }, [token, seccion])

  useEffect(() => {
    void cargar()
  }, [cargar])

  async function guardar() {
    const serie = (filas: readonly Fila[]): Celda[][] =>
      filas.map((f) => [
        { tipo: 'texto', valor: f.nombre },
        { tipo: 'casilla', valor: f.canView },
        { tipo: 'casilla', valor: f.canModify },
        { tipo: 'casilla', valor: f.canDelete },
      ])

    const u = serializarTabla(serie(usuarios))
    if (!u.ok) {
      setAviso({ type: 'warning', title: u.fallo.title, text: u.fallo.text })
      return
    }
    const g = serializarTabla(serie(grupos))
    if (!g.ok) {
      setAviso({ type: 'warning', title: g.fallo.title, text: g.fallo.text })
      return
    }

    setOcupado(true)
    const outcome = await setPermissions(token, seccion, u.valor, g.valor, nodoPrimario)
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
      title={`Edit Permissions - ${seccion}`}
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
          <TablaPermisos
            titulo="User Permissions"
            cabecera="Username"
            filas={usuarios}
            onChange={setUsuarios}
          />
          <MRow label="Add User">
            {(id) => (
              <select
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
              </select>
            )}
          </MRow>

          <TablaPermisos
            titulo="Group Permissions"
            cabecera="Group"
            filas={grupos}
            onChange={setGrupos}
          />
          <MRow label="Add Group">
            {(id) => (
              <select
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
              </select>
            )}
          </MRow>
        </>
      )}
    </Dialog>
  )
}

const nuevaFila = (nombre: string): Fila => ({
  nombre,
  canView: false,
  canModify: false,
  canDelete: false,
})

/* `sortTable('tbodyEditPermissionsUser'|'Group', 0)`. */
const CLAVES_PERMISO: Claves<Fila> = { nombre: (f) => f.nombre }

function TablaPermisos({
  titulo,
  cabecera,
  filas,
  onChange,
}: {
  titulo: string
  cabecera: string
  filas: readonly Fila[]
  onChange: (f: readonly Fila[]) => void
}) {
  const { filas: visibles, orden, alternar } = useOrden(CLAVES_PERMISO, filas as Fila[])

  // La casilla escribe sobre la lista ORIGINAL: la ordenación sólo cambia el
  // orden en que se pinta, no el de los datos.
  function set(fila: Fila, parcial: Partial<Fila>) {
    onChange(filas.map((f) => (f.nombre === fila.nombre ? { ...f, ...parcial } : f)))
  }

  return (
    <>
      <p className={styles.sub}>{titulo}</p>
      <div className={tbl.wrap}>
        <table className={styles.edit}>
          <thead>
            <tr>
              <Th campo="nombre" orden={orden} onOrdenar={alternar}>{cabecera}</Th>
              <th>View</th>
              <th>Modify</th>
              <th>Delete</th>
              <th className={styles.tdel} />
            </tr>
          </thead>
          <tbody>
            {visibles.map((f) => (
              <tr key={f.nombre}>
                <td className={styles.who}>{f.nombre}</td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`${f.nombre} View`}
                    checked={f.canView}
                    onChange={(e) => set(f, { canView: e.target.checked })}
                  />
                </td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`${f.nombre} Modify`}
                    checked={f.canModify}
                    onChange={(e) => set(f, { canModify: e.target.checked })}
                  />
                </td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`${f.nombre} Delete`}
                    checked={f.canDelete}
                    onChange={(e) => set(f, { canDelete: e.target.checked })}
                  />
                </td>
                <td className={styles.tdel}>
                  <Button onClick={() => onChange(filas.filter((x) => x.nombre !== f.nombre))}>Remove</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {/* Upstream no pone ningún texto cuando la tabla del modal está vacía;
            aquí tampoco, para no inventar un literal que no existe. */}
      </div>
    </>
  )
}
