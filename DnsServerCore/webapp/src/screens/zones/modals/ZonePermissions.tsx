import { useEffect, useState } from 'react'
import { getZonePermissions, serializePermissions, setZonePermissions } from '../../../api/zones'
import { Button } from '../../../ui/Button'
import { Dialog } from '../../../ui/Dialog'
import { Field, Select } from '../../../ui/Field'
import { Loading } from '../../../ui/Empty'
import type { Notice } from '../types'
import { Table } from '../../../ui/Table'
import styles from '../Zones.module.css'
import { noticeFromFailure } from '../../../lib/notice'
import { Notifier } from '../../../ui/Notifier'

/*
`modalEditPermissions` for a zone (zone.js:2544 and 2616).

Two tables identical in appearance —users and groups— with the catch that **the
subject's name is called something different in each**: `username` in users and
`name` in groups. Here they are normalised to `nombre` on the way in and
serialised back the same on the way out, which is all the server sees.

The "add" dropdown carries two phantom entries from upstream —an empty one and
one that says "None"— that add nobody. They are kept.
*/

interface Row {
  name: string
  canView: boolean
  canModify: boolean
  canDelete: boolean
}

export function ZonePermissions({
  zone,
  open,
  token,
  node = '',
  canModify,
  onClose,
  onHecho,
}: {
  zone: string
  open: boolean
  token: string | null
  node?: string
  canModify: boolean
  onClose: () => void
  onHecho: (a: Notice) => void
}) {
  /* Upstream titles it `Edit Permissions - <span>` (`index.html:6856`) and fills
     that span with `"Zones / " + zone` (`zone.js:2549`). Without the prefix, the
     dialog does not say what it does: it is the only one of Zones' ten whose title
     does not name the action, and the same dialog opened from Administration does
     carry it. */
  const [title, setTitle] = useState(
    `Edit Permissions - Zones / ${zone === '.' ? '<root>' : zone}`,
  )
  const [users, setUsers] = useState<Row[]>([])
  const [groups, setGroups] = useState<Row[]>([])
  const [availableUsers, setAvailableUsers] = useState<string[]>([])
  const [availableGroups, setAvailableGroups] = useState<string[]>([])
  const [notice, setNotice] = useState<Notice | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setLoading(true)
    void getZonePermissions(token, zone, node).then((r) => {
      setLoading(false)
      if (r == null) {
        setNotice({ type: 'danger', title: 'Error!', text: 'Unable to reach the DNS server.' })
        return
      }
      setTitle(`Edit Permissions - ${r.section} / ${r.subItem === '.' ? '<root>' : r.subItem}`)
      setUsers(
        r.userPermissions.map((p) => ({
          name: p.username,
          canView: p.canView,
          canModify: p.canModify,
          canDelete: p.canDelete,
        })),
      )
      setGroups(
        r.groupPermissions.map((p) => ({
          name: p.name,
          canView: p.canView,
          canModify: p.canModify,
          canDelete: p.canDelete,
        })),
      )
      setAvailableUsers(r.users ?? [])
      setAvailableGroups(r.groups ?? [])
    })
  }, [open, token, zone, node])

  async function save() {
    setBusy(true)
    const outcome = await setZonePermissions(
      token,
      zone,
      serializePermissions(users),
      serializePermissions(groups),
      node,
    )
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }

    onClose()
    onHecho({ type: 'success', title: 'Permissions Saved!', text: 'Zone permissions were saved successfully.' })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="medium"
      title={title}
      actions={
        <>
          {canModify && (
            <Button variant="primary" disabled={busy || loading} onClick={() => void save()}>
              Save
            </Button>
          )}
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />

      {loading ? (
        <Loading>Loading permissions…</Loading>
      ) : (
        <div className={styles.fields}>
          <PermissionsTable
            title="User Permissions"
            rows={users}
            disponibles={availableUsers}
            addLabel="Add User"
            onCambiar={setUsers}
          />
          <PermissionsTable
            title="Group Permissions"
            rows={groups}
            disponibles={availableGroups}
            addLabel="Add Group"
            onCambiar={setGroups}
          />
        </div>
      )}
    </Dialog>
  )
}

function PermissionsTable({
  title,
  rows,
  disponibles,
  addLabel,
  onCambiar,
}: {
  title: string
  rows: Row[]
  disponibles: string[]
  addLabel: string
  onCambiar: (f: Row[]) => void
}) {
  const unassigned = disponibles.filter((d) => !rows.some((f) => f.name === d))

  const cambiar = (i: number, key: keyof Row, value: boolean) =>
    onCambiar(rows.map((f, j) => (j === i ? { ...f, [key]: value } : f)))

  return (
    <div className={styles.group}>
      <div className={styles.groupTitle}>{title}</div>

      {rows.length === 0 ? (
        <div className={styles.help}>No permissions assigned.</div>
      ) : (
        <Table
          header={
            <>
              <th>Name</th>
              <th style={{ width: 70 }}>View</th>
              <th style={{ width: 70 }}>Modify</th>
              <th style={{ width: 70 }}>Delete</th>
              <th style={{ width: 90 }} />
            </>
          }
        >
          {rows.map((f, i) => (
            <tr key={f.name}>
              <td className={styles.mono}>{f.name}</td>
              {(['canView', 'canModify', 'canDelete'] as const).map((key) => (
                <td key={key}>
                  <input
                    type="checkbox"
                    className={styles.chkPerm}
                    aria-label={`${key} for ${f.name}`}
                    checked={f[key]}
                    onChange={(e) => cambiar(i, key, e.target.checked)}
                  />
                </td>
              ))}
              <td>
                <Button
                  size="sm"
                  onClick={() => onCambiar(rows.filter((_, j) => j !== i))}
                >
                  Remove
                </Button>
              </td>
            </tr>
          ))}
        </Table>
      )}

      <Field label={addLabel}>
        {(id) => (
          <Select
            id={id}
            value=""
            onChange={(e) => {
              const v = e.target.value
              // Upstream's two phantom entries add nobody.
              if (v === '' || v === 'none') return
              onCambiar([...rows, { name: v, canView: true, canModify: false, canDelete: false }])
            }}
          >
            <option value="" />
            <option value="none">None</option>
            {unassigned.map((d) => (
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
