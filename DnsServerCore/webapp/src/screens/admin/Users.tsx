import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { Input } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import { Tag } from '../../ui/Tag'
import {
  createUser,
  deleteUser,
  listUsers,
  resetUserPassword,
  setUser,
  type AdminUser,
} from '../../api/admin'
import type { ClusterState } from '../../api/admin-cluster'
import { UserDetails } from './UserDetails'
import { fechaHora } from './dates'
import {
  noticeFromFailure,
  Confirm,
  MRow,
  adminStyles as styles,
  type Notice,
} from './parts'
import tbl from '../../ui/Table.module.css'
import { RowAction, Th, useOrden, type Keys, Table } from '../../ui/Table'
import { Menu, Separator } from '../../ui/Menu'
import { neverUsed } from '../../api/zones'
import { Notifier } from '../../ui/Notifier'

/*
`refreshAdminUsers` and the row's seven actions (auth.js:1083-1698).

Five of those seven actions —saving the modal, enabling, disabling, clearing the
2FA and resetting the password— go out through the SAME `admin/users/set`
endpoint, because the server only touches the fields that arrive. The sixth and
seventh are `admin/users/create` and `admin/users/delete`.

Two asymmetries of upstream's that are replicated as they are:

  · Disabling asks for confirmation; ENABLING does not.
  · "Reset Password" and "Disable 2FA" are only offered to a local user, and
    "Disable 2FA" only if they have it on (auth.js:1150-1157).
*/

interface Props {
  token: string | null
  cluster: ClusterState | null
  onNotice: (a: Notice) => void
}

type Action =
  | { type: 'disable'; user: AdminUser }
  | { type: '2fa'; user: AdminUser }
  | { type: 'delete'; user: AdminUser }

/** The date of a login, or "Never" if it is .NET's sentinel. */
function access(iso: string, address: string): string {
  return neverUsed(iso) ? 'Never' : `${fechaHora(iso)} from ${address}`
}

/* `sortTable('tbodyAdminUsers', 0..6)`. */
const KEYS: Keys<AdminUser> = {
  username: (u) => u.username,
  display: (u) => u.displayName,
  type: (u) => (u.isSsoUser ? 'Remote/SSO' : 'Local'),
  totp: (u) => (u.isSsoUser ? 'SSO Managed' : u.totpEnabled ? 'Enabled' : 'Disabled'),
  status: (u) => (u.disabled ? 'Disabled' : 'Enabled'),
  recent: (u) => access(u.recentSessionLoggedOn, u.recentSessionRemoteAddress),
  previous: (u) => access(u.previousSessionLoggedOn, u.previousSessionRemoteAddress),
}

export function Users({ token, cluster, onNotice }: Props) {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [add, setAdd] = useState(false)
  const [reset, setReset] = useState<string | null>(null)
  const [detail, setDetalle] = useState<string | null>(null)
  const [action, setAction] = useState<Action | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const outcome = await listUsers(token)
    setLoading(false)

    if (outcome.kind !== 'ok') {
      setUsers([])
      onNotice(noticeFromFailure(outcome))
      return
    }
    setUsers(outcome.data.response.users)
  }, [token, onNotice])

  useEffect(() => {
    void load()
  }, [load])

  const { rows: visibleUsers, sort, toggle } = useOrden(KEYS, users)

  function reemplazar(u: AdminUser) {
    setUsers((list) => list.map((x) => (x.username === u.username ? u : x)))
  }

  /** Changing the username from the modal leaves the row with no match by
   *  `username`; upstream replaces it by position. Here it is done by the index
   *  of the user that was opened, which is the same thing. */
  function reemplazarPor(previous: string, u: AdminUser) {
    setUsers((list) => list.map((x) => (x.username === previous ? u : x)))
  }

  async function change(u: AdminUser, body: Record<string, string>, notice: Notice) {
    setAction(null)
    const outcome = await setUser(token, { user: u.username, ...body })
    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    reemplazar(outcome.data.response)
    onNotice(notice)
  }

  async function remove(u: AdminUser) {
    setAction(null)
    const outcome = await deleteUser(token, u.username)
    if (outcome.kind !== 'ok') {
      onNotice(noticeFromFailure(outcome))
      return
    }
    setUsers((list) => list.filter((x) => x.username !== u.username))
    onNotice({ type: 'success', title: 'User Deleted!', text: 'User account was deleted successfully.' })
  }

  return (
    <>
      <SectionHeader
        section="Administration"
        title="Users"
        actions={<><Button variant="primary" onClick={() => setAdd(true)}>
            Add User
          </Button></>}
      />

      {loading ? (
        <Loading />
      ) : (
        <>
          <Table
            header={
              <>
                <Th field="username" sort={sort} onSort={toggle}>Username</Th>
                <Th field="display" sort={sort} onSort={toggle}>Display Name</Th>
                <Th field="type" sort={sort} onSort={toggle}>Type</Th>
                <Th field="totp" sort={sort} onSort={toggle}>2FA Status</Th>
                <Th field="status" sort={sort} onSort={toggle}>Status</Th>
                <Th field="recent" sort={sort} onSort={toggle}>Recent Login</Th>
                <Th field="previous" sort={sort} onSort={toggle}>Previous Login</Th>
                <th className={tbl.actionsCell} />
              </>
            }
            isEmpty={visibleUsers.length === 0}
            emptyText="No User Found"
            columns={8}
          >
            {visibleUsers.map((u) => (
              <tr key={u.username}>
                <td>
                  <button
                    type="button"
                    className={styles.link}
                    onClick={() => setDetalle(u.username)}
                  >
                    {u.username}
                  </button>
                </td>
                <td>{u.displayName}</td>
                <td>{u.isSsoUser ? 'Remote/SSO' : 'Local'}</td>
                <td>
                  {u.isSsoUser ? (
                    <Tag tone="info">SSO Managed</Tag>
                  ) : u.totpEnabled ? (
                    <Tag tone="ok">Enabled</Tag>
                  ) : (
                    <Tag>Disabled</Tag>
                  )}
                </td>
                <td>
                  {u.disabled ? (
                    <Tag>Disabled</Tag>
                  ) : (
                    <Tag tone="ok">Enabled</Tag>
                  )}
                </td>
                {/*
                Upstream formats the date without checking whether it is .NET's
                minimum (auth.js:1141), so for a user who has never logged in it
                shows "0000-12-31 23:45:16 from 0.0.0.0" —year zero, because it
                converts to local time a date older than time zones— and an
                address that does not exist. That is not a datum: it is a
                sentinel value leaking onto the screen. It says "Never", which is
                what it means, just as was done with the DNSSEC column.
                */}
                <td className={styles.mono}>{access(u.recentSessionLoggedOn, u.recentSessionRemoteAddress)}</td>
                <td className={styles.mono}>{access(u.previousSessionLoggedOn, u.previousSessionRemoteAddress)}</td>
                <td className={tbl.actionsCell}>
                  <div className={tbl.actions}>
                    <RowAction
                      icon="card"
                      name="View Details"
                      onClick={() => setDetalle(u.username)}
                    />
                    <RowAction
                      icon="power"
                      name={u.disabled ? 'Enable User' : 'Disable User'}
                      onClick={() =>
                        u.disabled
                          ? void change(u, { disabled: 'false' }, {
                              type: 'success',
                              title: 'User Enabled!',
                              text: `User [${u.username}] account was enabled successfully.`,
                            })
                          : setAction({ type: 'disable', user: u })
                      }
                    />
                    <Menu label={`Actions for ${u.username}`}>
                      {(close) => (
                        <>
                          {!u.isSsoUser && (
                            <button type="button" onClick={() => { close(); setReset(u.username) }}>
                              Reset Password
                            </button>
                          )}
                          {!u.isSsoUser && u.totpEnabled && (
                            <button type="button" onClick={() => { close(); setAction({ type: '2fa', user: u }) }}>
                              Disable 2FA
                            </button>
                          )}
                          <Separator />
                          <button type="button" data-variant="danger" onClick={() => { close(); setAction({ type: 'delete', user: u }) }}>
                            Delete User
                          </button>
                        </>
                      )}
                    </Menu>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
          <div className={styles.count}>
            <span>{`Total Users: ${users.length}`}</span>
          </div>
        </>
      )}

      <Confirm
        open={action?.type === 'disable'}
        title="Disable User"
        text={`Are you sure you want to disable the user [${action?.user.username ?? ''}] account?`}
        label="Disable"
        onClose={() => setAction(null)}
        onConfirm={() =>
          action?.type === 'disable' &&
          void change(action.user, { disabled: 'true' }, {
            type: 'success',
            title: 'User Disabled!',
            text: `User [${action.user.username}] account was disabled successfully.`,
          })
        }
      />

      <Confirm
        open={action?.type === '2fa'}
        title="Disable 2FA"
        text={`Are you sure you want to disable Two-factor authentication (2FA) for user [${action?.user.username ?? ''}] ?`}
        label="Disable"
        onClose={() => setAction(null)}
        onConfirm={() =>
          action?.type === '2fa' &&
          void change(action.user, { totpEnabled: 'false' }, {
            type: 'success',
            title: '2FA Disabled!',
            text: `Two-factor authentication was disabled successfully for user [${action.user.username}].`,
          })
        }
      />

      <Confirm
        open={action?.type === 'delete'}
        title="Delete User"
        text={`Are you sure you want to delete the user [${action?.user.username ?? ''}] account?`}
        label="Delete"
        onClose={() => setAction(null)}
        onConfirm={() => action?.type === 'delete' && void remove(action.user)}
      />

      <AddUser
        open={add}
        token={token}
        onClose={() => setAdd(false)}
        onAdded={(u) => {
          setUsers((list) => [u, ...list])
          onNotice({ type: 'success', title: 'User Added!', text: 'User was added successfully.' })
        }}
      />

      {reset != null && (
        <ResetPassword
          username={reset}
          token={token}
          onClose={() => setReset(null)}
          onNotice={onNotice}
        />
      )}

      {detail != null && (
        <UserDetails
          open
          username={detail}
          token={token}
          cluster={cluster}
          onClose={() => setDetalle(null)}
          onSaved={(u) => reemplazarPor(detail, u)}
          onNotice={onNotice}
        />
      )}
    </>
  )
}

/* `addUser` (auth.js:1178). The order of the four validations is contract. */
function AddUser({
  open,
  token,
  onClose,
  onAdded,
}: {
  open: boolean
  token: string | null
  onClose: () => void
  onAdded: (u: AdminUser) => void
}) {
  const [displayName, setDisplayName] = useState('')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setNotice(null)
    setDisplayName('')
    setUser('')
    setPass('')
    setConfirm('')
  }, [open])

  async function add() {
    if (user === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter an username to add user.' })
      return
    }
    if (pass === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter a password to add user.' })
      return
    }
    if (confirm === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter confirm password.' })
      return
    }
    if (pass !== confirm) {
      setNotice({
        type: 'warning',
        title: 'Mismatch!',
        text: 'Passwords do not match. Please try again.',
      })
      return
    }

    setBusy(true)
    const outcome = await createUser(token, displayName, user, pass)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onAdded(outcome.data.response)
    onClose()
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Add User"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void add()}>
            Add
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <MRow label="Display Name">
        {(id) => (
          <Input
            id={id}
            placeholder="display name"
            maxLength={255}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Username">
        {(id) => (
          <Input
            id={id}
            placeholder="username"
            maxLength={255}
            value={user}
            onChange={(e) => setUser(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            placeholder="password"
            maxLength={255}
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Confirm Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            placeholder="confirm password"
            maxLength={255}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}

/*
`showResetUserPasswordModal` / `resetUserPassword` (auth.js:1546-1627). Upstream
REUSES the "Change Password" modal by changing its title to "Reset Password",
hiding the current password and the OTP, and renaming the button to "Reset". The
success alert comes out on the PAGE, because the modal has already closed.
*/
function ResetPassword({
  username,
  token,
  onClose,
  onNotice,
}: {
  username: string
  token: string | null
  onClose: () => void
  onNotice: (a: Notice) => void
}) {
  const [blank, setNueva] = useState('')
  const [confirm, setConfirm] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState(false)

  async function save() {
    if (blank === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter new password.' })
      return
    }
    if (confirm === '') {
      setNotice({ type: 'warning', title: 'Missing!', text: 'Please enter confirm password.' })
      return
    }
    if (blank !== confirm) {
      setNotice({
        type: 'warning',
        title: 'Mismatch!',
        text: 'Passwords do not match. Please try again.',
      })
      return
    }

    setBusy(true)
    const outcome = await resetUserPassword(token, username, blank)
    setBusy(false)

    if (outcome.kind !== 'ok') {
      setNotice(noticeFromFailure(outcome))
      return
    }
    onClose()
    onNotice({ type: 'success', title: 'Password Reset!', text: 'Password was reset successfully.' })
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Reset Password"
      actions={
        <>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>
            Reset
          </Button>
        </>
      }
    >
      <Notifier notice={notice} onClose={() => setNotice(null)} />
      <MRow label="Username">{(id) => <Input id={id} value={username} readOnly />}</MRow>
      <MRow label="New Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            maxLength={255}
            value={blank}
            onChange={(e) => setNueva(e.target.value)}
          />
        )}
      </MRow>
      <MRow label="Confirm Password">
        {(id) => (
          <Input
            id={id}
            type="password"
            maxLength={255}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        )}
      </MRow>
    </Dialog>
  )
}
