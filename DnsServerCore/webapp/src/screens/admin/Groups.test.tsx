import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Groups } from './Groups'
import * as client from '../../api/client'
import { GROUPS } from './admin.fixture'
import { choose } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(groups = GROUPS, detalle?: Record<string, unknown>) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/groups/list') return ok({ response: { groups: groups }, server: 'x' })
    if (path === 'admin/groups/get') {
      return ok({
        response: detalle ?? {
          name: 'Administrators',
          description: 'Super administrators',
          members: ['admin'],
          users: ['admin', 'testuser'],
        },
        server: 'x',
      })
    }
    if (path === 'admin/groups/create') {
      return ok({ response: { name: 'Ops', description: 'los de guardia' }, server: 'x' })
    }
    if (path === 'admin/groups/set') {
      return ok({ response: { name: 'Otros', description: 'Super administrators' }, server: 'x' })
    }
    return ok({ response: {}, server: 'x' })
  })
}

const props = { token: 'tok', onAviso: vi.fn() }

describe('Groups — the table', () => {
  it('it draws name, description and the total', async () => {
    servidor()
    render(<Groups {...props} />)
    expect(await screen.findByText('Super administrators')).toBeInTheDocument()
    expect(screen.getByText('Total Groups: 3')).toBeInTheDocument()
  })

  it('a description with newlines is drawn over several lines', async () => {
    servidor([{ name: 'Ops', description: 'first line\nsecond line' }])
    render(<Groups {...props} />)
    expect(await screen.findByText('first line')).toBeInTheDocument()
    expect(screen.getByText('second line')).toBeInTheDocument()
  })

  it('with no groups the total says zero', async () => {
    servidor([])
    render(<Groups {...props} />)
    expect(await screen.findByText('Total Groups: 0')).toBeInTheDocument()
  })

  it('if the server fails it alerts with its message', async () => {
    const onAviso = vi.fn()
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Access was denied.' })
    render(<Groups {...props} onAviso={onAviso} />)
    expect(await screen.findByText('Total Groups: 0')).toBeInTheDocument()
    expect(onAviso).toHaveBeenCalledWith({
      type: 'danger',
      title: 'Error!',
      text: 'Access was denied.',
    })
  })
})

describe('Groups — "Add Group"', () => {
  it('it requires the name and nothing else', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Add Group' }))
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByText('Please enter a name to add group.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/create')).toBeUndefined()
  })

  it('it creates the group with its description and puts it first in the list', async () => {
    const spy = servidor()
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Groups {...props} onAviso={onAviso} />)

    await user.click(await screen.findByRole('button', { name: 'Add Group' }))
    await user.type(screen.getByLabelText('Name'), 'Ops')
    await user.type(screen.getByLabelText('Description'), 'los de guardia')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/create')?.[1]).toEqual({
      token: 'tok',
      body: { group: 'Ops', description: 'los de guardia' },
    })
    expect(screen.getByText('Total Groups: 4')).toBeInTheDocument()
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Group Added!',
      text: 'Group was added successfully.',
    })
  })
})

describe('Groups — the details modal', () => {
  it('it saves cleaned members and WITHOUT `newGroup` if the name did not change', async () => {
    const spy = servidor()
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Groups {...props} onAviso={onAviso} />)

    await user.click((await screen.findAllByRole('button', { name: 'View Details' }))[0])
    await screen.findByLabelText('Members')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/set')?.[1]).toEqual({
      token: 'tok',
      body: { group: 'Administrators', description: 'Super administrators', members: 'admin' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Group Saved!',
      text: 'Group details were saved successfully.',
    })
  })

  it('`newGroup` travels when the name changes', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click((await screen.findAllByRole('button', { name: 'View Details' }))[0])
    const name = await screen.findByLabelText('Name')
    await user.clear(name)
    await user.type(name, 'Otros')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/groups/set')?.[1]?.body as Record<string, string>
    expect(body.newGroup).toBe('Otros')
    expect(body.group).toBe('Administrators')
  })

  it('\"Add User\" appends at the end and \"None\" empties the member list', async () => {
    servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click((await screen.findAllByRole('button', { name: 'View Details' }))[0])
    const add = await screen.findByLabelText('Add User')

    await choose(user, add, 'testuser')
    expect(screen.getByLabelText('Members')).toHaveValue('admin\ntestuser\n')

    await choose(user, add, 'None')
    expect(screen.getByLabelText('Members')).toHaveValue('')
  })

  it('deleting asks for confirmation with the name and takes the row out', async () => {
    const spy = servidor()
    const onAviso = vi.fn()
    const user = userEvent.setup()
    render(<Groups {...props} onAviso={onAviso} />)

    await user.click((await screen.findAllByRole('button', { name: /^Actions for / }))[0])
    await user.click(await screen.findByRole('button', { name: 'Delete Group' }))
    expect(
      screen.getByText('Are you sure you want to delete the group [Administrators] ?'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/delete')?.[1]).toEqual({
      token: 'tok',
      body: { group: 'Administrators' },
    })
    expect(screen.getByText('Total Groups: 2')).toBeInTheDocument()
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Group Deleted!',
      text: 'Group was deleted successfully.',
    })
  })
})
