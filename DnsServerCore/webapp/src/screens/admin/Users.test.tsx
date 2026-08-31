import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Users } from './Users'
import * as client from '../../api/client'
import { USER_DETAIL, ADMIN_USER, NEW_USER, SSO_USER } from './admin.fixture'
import { choose } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(users = [ADMIN_USER, NEW_USER], detail = USER_DETAIL) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string, opts) => {
    if (path === 'admin/users/list') return ok({ response: { users: users }, server: 'x' })
    if (path === 'admin/users/get') return ok({ response: detail, server: 'x' })
    if (path === 'admin/users/set') {
      const body = (opts?.body ?? {}) as Record<string, string>
      return ok({
        response: { ...detail, disabled: body.disabled === 'true', totpEnabled: false },
        server: 'x',
      })
    }
    if (path === 'admin/users/create') {
      return ok({ response: { ...NEW_USER, username: 'nuevo' }, server: 'x' })
    }
    return ok({ response: {}, server: 'x' })
  })
}

const props = { token: 'tok', cluster: null, onNotice: vi.fn() }

describe('Users — the table', () => {
  it('it draws type, 2FA, state and the two logins, with the total', async () => {
    servidor()
    render(<Users {...props} />)

    expect(await screen.findByText('Administrator')).toBeInTheDocument()
    expect(screen.getAllByText('Local')).toHaveLength(2)
    expect(screen.getByText('Total Users: 2')).toBeInTheDocument()
    // `0001-01-01T00:00:00` is .NET's "never". Upstream formats it without
    // looking and produces "0000-12-31 23:45:16 from 0.0.0.0"; here it says
    // "Never", which is what that value means.
    expect(screen.getAllByText('Never')).toHaveLength(2)
    expect(screen.queryByText(/from 0\.0\.0\.0/)).toBeNull()
  })

  it('an SSO user comes out as Remote/SSO and with the 2FA managed elsewhere', async () => {
    servidor([SSO_USER])
    render(<Users {...props} />)
    expect(await screen.findByText('Remote/SSO')).toBeInTheDocument()
    expect(screen.getByText('SSO Managed')).toBeInTheDocument()
  })

  it('an SSO user is offered neither a password reset nor clearing the 2FA', async () => {
    servidor([SSO_USER])
    render(<Users {...props} />)
    await screen.findByText('Remote/SSO')
    expect(screen.queryByRole('button', { name: 'Reset Password' })).not.toBeInTheDocument()
    await userEvent.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    expect(screen.queryByRole('button', { name: 'Disable 2FA' })).not.toBeInTheDocument()
  })

  it('\"Disable 2FA\" only appears if the user has it on', async () => {
    servidor([{ ...NEW_USER, totpEnabled: true }])
    render(<Users {...props} />)
    await userEvent.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()
  })

  it('with no users the total says zero', async () => {
    servidor([])
    render(<Users {...props} />)
    expect(await screen.findByText('Total Users: 0')).toBeInTheDocument()
  })
})

describe('Users — enable and disable', () => {
  it('ENABLING asks for no confirmation: it goes straight out', async () => {
    const spy = servidor([{ ...NEW_USER, disabled: true }])
    const onNotice = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onNotice={onNotice} />)

    await user.click(await screen.findByRole('button', { name: 'Enable User' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser', disabled: 'false' },
    })
    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Enabled!',
      text: 'User [testuser] account was enabled successfully.',
    })
  })

  it('DISABLING does ask for confirmation, with the name in the text', async () => {
    const spy = servidor([NEW_USER])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Disable User' }))
    expect(
      screen.getByText('Are you sure you want to disable the user [testuser] account?'),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')).toBeUndefined()
  })

  it('clearing the 2FA sends `totpEnabled=false` and alerts with the upstream literal', async () => {
    const spy = servidor([{ ...NEW_USER, totpEnabled: true }])
    const onNotice = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onNotice={onNotice} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Disable 2FA' }))
    expect(
      screen.getByText(
        'Are you sure you want to disable Two-factor authentication (2FA) for user [testuser] ?',
      ),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Disable' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser', totpEnabled: 'false' },
    })
    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: '2FA Disabled!',
      text: 'Two-factor authentication was disabled successfully for user [testuser].',
    })
  })

  it('deleting asks for confirmation and takes the row out of the table', async () => {
    const spy = servidor([ADMIN_USER, NEW_USER])
    const onNotice = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onNotice={onNotice} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[1])
    await user.click(await screen.findByRole('button', { name: 'Delete User' }))
    expect(
      screen.getByText('Are you sure you want to delete the user [testuser] account?'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/delete')?.[1]).toEqual({
      token: 'tok',
      body: { user: 'testuser' },
    })
    expect(screen.getByText('Total Users: 1')).toBeInTheDocument()
    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Deleted!',
      text: 'User account was deleted successfully.',
    })
  })
})

describe('Users — "Add User"', () => {
  async function open() {
    servidor()
    const user = userEvent.setup()
    render(<Users {...props} />)
    await user.click(await screen.findByRole('button', { name: 'Add User' }))
    await screen.findByLabelText('Confirm Password')
    return user
  }

  it('the order of the four validations is the one of upstream', async () => {
    const user = await open()
    const add = screen.getByRole('button', { name: 'Add' })

    await user.click(add)
    expect(screen.getByText('Please enter an username to add user.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Username'), 'nuevo')
    await user.click(add)
    expect(screen.getByText('Please enter a password to add user.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Password'), 'uno')
    await user.click(add)
    expect(screen.getByText('Please enter confirm password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Confirm Password'), 'dos')
    await user.click(add)
    expect(screen.getByText('Passwords do not match. Please try again.')).toBeInTheDocument()
  })

  it('the display name is optional: it is not validated', async () => {
    const user = await open()
    await user.type(screen.getByLabelText('Username'), 'nuevo')
    await user.type(screen.getByLabelText('Password'), 'x')
    await user.type(screen.getByLabelText('Confirm Password'), 'x')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    const spy = vi.mocked(client.apiRequest)
    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/create')?.[1]).toEqual({
      token: 'tok',
      method: 'POST',
      body: { displayName: '', user: 'nuevo', pass: 'x' },
    })
  })
})

describe('Users — "Reset Password"', () => {
  it('it validates in order and saves by POST with `newPass`', async () => {
    const spy = servidor([NEW_USER])
    const onNotice = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onNotice={onNotice} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Reset Password' }))
    const reset = screen.getByRole('button', { name: 'Reset' })

    await user.click(reset)
    expect(screen.getByText('Please enter new password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('New Password'), 'uno')
    await user.click(reset)
    expect(screen.getByText('Please enter confirm password.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Confirm Password'), 'dos')
    await user.click(reset)
    expect(screen.getByText('Passwords do not match. Please try again.')).toBeInTheDocument()

    await user.clear(screen.getByLabelText('Confirm Password'))
    await user.type(screen.getByLabelText('Confirm Password'), 'uno')
    await user.click(reset)

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      method: 'POST',
      body: { user: 'testuser', newPass: 'uno' },
    })
    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: 'Password Reset!',
      text: 'Password was reset successfully.',
    })
  })
})

describe('Users — the details modal', () => {
  it('it sends user, state and session timeout, and the display name if not SSO', async () => {
    const spy = servidor([NEW_USER])
    const onNotice = vi.fn()
    const user = userEvent.setup()
    render(<Users {...props} onNotice={onNotice} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    await screen.findByLabelText('Session Timeout')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]).toEqual({
      token: 'tok',
      body: {
        user: 'testuser',
        disabled: 'false',
        sessionTimeoutSeconds: '1800',
        displayName: 'Test User',
        memberOfGroups: '',
      },
    })
    expect(onNotice).toHaveBeenCalledWith({
      type: 'success',
      title: 'User Saved!',
      text: 'User details were saved successfully.',
    })
  })

  it('an empty session timeout falls to the 1800 default, it does not travel empty', async () => {
    const spy = servidor([NEW_USER])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    await user.clear(await screen.findByLabelText('Session Timeout'))
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.sessionTimeoutSeconds).toBe('1800')
  })

  it('\"Add Group\" adds the group to the list and \"None\" empties it', async () => {
    const spy = servidor([NEW_USER])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const add = await screen.findByLabelText('Add Group')

    await choose(user, add, 'Administrators')
    expect(screen.getByLabelText('Member Of')).toHaveValue('Administrators\n')

    await choose(user, add, 'DNS Administrators')
    expect(screen.getByLabelText('Member Of')).toHaveValue('Administrators\nDNS Administrators\n')

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    // `cleanTextList`: newlines to commas, no trailing comma.
    expect(body.memberOfGroups).toBe('Administrators,DNS Administrators')
  })

  it('an SSO user has name and display name locked, and does not send them', async () => {
    const spy = servidor([SSO_USER], {
      ...USER_DETAIL,
      ...SSO_USER,
      ssoManagedGroups: false,
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    expect(await screen.findByLabelText('Display Name')).toBeDisabled()
    expect(screen.getByLabelText('Username')).toBeDisabled()
    // With `ssoManagedGroups` false the groups CAN be touched: they are two
    // different conditions, not one.
    expect(screen.getByLabelText('Member Of')).not.toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.displayName).toBeUndefined()
    expect(body.newUser).toBeUndefined()
    expect(body.memberOfGroups).toBe('')
  })

  it('with `ssoManagedGroups` the groups are locked too and left out of the send', async () => {
    const spy = servidor([SSO_USER], {
      ...USER_DETAIL,
      ...SSO_USER,
      ssoManagedGroups: true,
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    expect(await screen.findByLabelText('Member Of')).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Save' }))
    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.memberOfGroups).toBeUndefined()
  })

  it('`newUser` only travels when the name changes', async () => {
    const spy = servidor([NEW_USER])
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const field = await screen.findByLabelText('Username')
    await user.clear(field)
    await user.type(field, 'otro')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/users/set')?.[1]?.body as Record<string, string>
    expect(body.newUser).toBe('otro')
  })

  it('the sessions of the user come out inside the modal with their own total', async () => {
    servidor([NEW_USER], {
      ...USER_DETAIL,
      sessions: [
        {
          username: 'testuser',
          isCurrentSession: false,
          partialToken: '799a4919af7636e2',
          type: 'ApiToken',
          tokenName: 'tok1',
          lastSeen: '2026-08-26T05:29:41Z',
          lastSeenRemoteAddress: '172.23.0.1',
          lastSeenUserAgent: 'curl/8.18.0',
        },
      ],
    })
    const user = userEvent.setup()
    render(<Users {...props} />)

    await user.click(await screen.findByRole('button', { name: 'View Details' }))
    const dialogo = await screen.findByRole('dialog')
    expect(within(dialogo).getByText('Total Sessions: 1')).toBeInTheDocument()
    expect(within(dialogo).getByText('[799a4919af7636e2]')).toBeInTheDocument()
  })
})
