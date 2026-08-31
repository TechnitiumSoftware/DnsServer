import { useEffect, useState } from 'react'
import { getZonePermissions, serializarPermisos, setZonePermissions } from '../../../api/zones'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Select } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import type { Aviso } from '../tipos'
import { Tabla } from '../../../ui/Table'
import styles from '../Zones.module.css'
import { avisoDeFallo } from '../../../lib/aviso'
import { Avisador } from '../../../ui/Avisador'

/*
`modalEditPermissions` for a zone (zone.js:2544 and 2616).

Two tables identical in appearance —users and groups— with the catch that **the
subject's name is called something different in each**: `username` in users and
`name` in groups. Here they are normalised to `nombre` on the way in and
serialised back the same on the way out, which is all the server sees.

The "add" dropdown carries two phantom entries from upstream —an empty one and
one that says "None"— that add nobody. They are kept.
*/

interface Fila {
  nombre: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export function PermisosZona({
  zone,
  abierto,
  token,
  node = '',
  canModify,
  onCerrar,
  onHecho,
}: {
  zone: string
  abierto: boolean
  token: string | null
  node?: string
  canModify: boolean
  onCerrar: () => void
  onHecho: (a: Aviso) => void
}) {
  /* Upstream titles it `Edit Permissions - <span>` (`index.html:6856`) and fills
     that span with `"Zones / " + zone` (`zone.js:2549`). Without the prefix, the
     dialog does not say what it does: it is the only one of Zones' ten whose title
     does not name the action, and the same dialog opened from Administration does
     carry it. */
  const [titulo, setTitulo] = useState(
    `Edit Permissions - Zones / ${zone === '.' ? '<root>' : zone}`,
  )
  const [usuarios, setUsuarios] = useState<Fila[]>([])
  const [grupos, setGrupos] = useState<Fila[]>([])
  const [usuariosDisponibles, setUsuariosDisponibles] = useState<string[]>([])
  const [gruposDisponibles, setGruposDisponibles] = useState<string[]>([])
  const [aviso, setAviso] = useState<Aviso | null>(null)
  const [cargando, setCargando] = useState(false)
  const [ocupado, setOcupado] = useState(false)

  useEffect(() => {
    if (!abierto) return
    setAviso(null)
    setCargando(true)
    void getZonePermissions(token, zone, node).then((r) => {
      setCargando(false)
      if (r == null) {
        setAviso({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setTitulo(`Edit Permissions - ${r.section} / ${r.subItem === '.' ? '<root>' : r.subItem}`)
      setUsuarios(
        r.userPermissions.map((p) => ({
          nombre: p.username,
          canView: p.canView,
          canModify: p.canModify,
          canDelete: p.canDelete,
        })),
      )
      setGrupos(
        r.groupPermissions.map((p) => ({
          nombre: p.name,
          canView: p.canView,
          canModify: p.canModify,
          canDelete: p.canDelete,
        })),
      )
      setUsuariosDisponibles(r.users ?? [])
      setGruposDisponibles(r.groups ?? [])
    })
  }, [abierto, token, zone, node])

  async function guardar() {
    setOcupado(true)
    const outcome = await setZonePermissions(
      token,
      zone,
      serializarPermisos(usuarios),
      serializarPermisos(grupos),
      node,
    )
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      setAviso(avisoDeFallo(outcome))
      return
    }

    onCerrar()
    onHecho({ type: 'success', title: 'Permissions Saved!', text: 'Zone permissions were saved successfully.' })
  }

  return (
    <Dialog
      open={abierto}
      onOpenChange={(o) => !o && onCerrar()}
      tamano="medio"
      title={titulo}
      acciones={
        <>
          {canModify && (
            <Button variant="primary" disabled={ocupado || cargando} onClick={() => void guardar()}>
              Save
            </Button>
          )}
        </>
      }
    >
      <Avisador aviso={aviso} onCerrar={() => setAviso(null)} />

      {cargando ? (
        <Loading>Loading permissions…</Loading>
      ) : (
        <div className={styles.campos}>
          <TablaPermisos
            titulo="User Permissions"
            filas={usuarios}
            disponibles={usuariosDisponibles}
            etiquetaAnadir="Add User"
            onCambiar={setUsuarios}
          />
          <TablaPermisos
            titulo="Group Permissions"
            filas={grupos}
            disponibles={gruposDisponibles}
            etiquetaAnadir="Add Group"
            onCambiar={setGrupos}
          />
        </div>
      )}
    </Dialog>
  )
}

function TablaPermisos({
  titulo,
  filas,
  disponibles,
  etiquetaAnadir,
  onCambiar,
}: {
  titulo: string
  filas: Fila[]
  disponibles: string[]
  etiquetaAnadir: string
  onCambiar: (f: Fila[]) => void
}) {
  const sinAsignar = disponibles.filter((d) => !filas.some((f) => f.nombre === d))

  const cambiar = (i: number, clave: keyof Fila, valor: boolean) =>
    onCambiar(filas.map((f, j) => (j === i ? { ...f, [clave]: valor } : f)))

  return (
    <div className={styles.grupo}>
      <div className={styles.grupoTit}>{titulo}</div>

      {filas.length === 0 ? (
        <div className={styles.ayuda}>No permissions assigned.</div>
      ) : (
        <Tabla
          cabecera={
            <>
              <th>Name</th>
              <th style={{ width: 70 }}>View</th>
              <th style={{ width: 70 }}>Modify</th>
              <th style={{ width: 70 }}>Delete</th>
              <th style={{ width: 90 }} />
            </>
          }
        >
          {filas.map((f, i) => (
            <tr key={f.nombre}>
              <td className={styles.mono}>{f.nombre}</td>
              {(['canView', 'canModify', 'canDelete'] as const).map((clave) => (
                <td key={clave}>
                  <input
                    type="checkbox"
                    className={styles.chkPerm}
                    aria-label={`${clave} for ${f.nombre}`}
                    checked={f[clave]}
                    onChange={(e) => cambiar(i, clave, e.target.checked)}
                  />
                </td>
              ))}
              <td>
                <Button
                  size="sm"
                  onClick={() => onCambiar(filas.filter((_, j) => j !== i))}
                >
                  Remove
                </Button>
              </td>
            </tr>
          ))}
        </Tabla>
      )}

      <Field label={etiquetaAnadir}>
        {(id) => (
          <Select
            id={id}
            value=""
            onChange={(e) => {
              const v = e.target.value
              // Upstream's two phantom entries add nobody.
              if (v === '' || v === 'none') return
              onCambiar([...filas, { nombre: v, canView: true, canModify: false, canDelete: false }])
            }}
          >
            <option value="" />
            <option value="none">None</option>
            {sinAsignar.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </Select>
        )}
      </Field>
    </div>
  )
}
