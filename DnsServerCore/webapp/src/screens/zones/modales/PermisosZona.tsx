import { useEffect, useState } from 'react'
import { getZonePermissions, serializarPermisos, setZonePermissions } from '../../../api/zones'
import { Alert } from '../../../ui/Alert'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Select } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import type { Aviso } from '../tipos'
import { Tabla } from '../../../ui/Table'
import styles from '../Zones.module.css'
import { avisoDeFallo } from '../../../lib/aviso'

/*
`modalEditPermissions` para una zona (zone.js:2544 y 2616).

Dos tablas idénticas en aspecto —usuarios y grupos— con la trampa de que **el
nombre del sujeto se llama distinto en cada una**: `username` en usuarios y
`name` en grupos. Aquí se normalizan a `nombre` al entrar y se vuelven a
serializar igual al salir, que es lo único que ve el servidor.

El desplegable de «añadir» lleva dos entradas fantasma de upstream —una vacía y
otra que dice «None»— que no añaden a nadie. Se conservan.
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
  /* Upstream titula `Edit Permissions - <span>` (`index.html:6856`) y rellena ese
     span con `"Zones / " + zone` (`zone.js:2549`). Sin el prefijo, el diálogo no
     dice qué hace: es el único de los diez de Zones cuyo título no nombra la
     acción, y el mismo diálogo abierto desde Administration sí lo lleva. */
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
      {aviso && (
        <div className={styles.avisoHueco}>
          <Alert type={aviso.type} title={aviso.title} onDismiss={() => setAviso(null)}>
            {aviso.text}
          </Alert>
        </div>
      )}

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
              // Las dos entradas fantasma de upstream no añaden a nadie.
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
