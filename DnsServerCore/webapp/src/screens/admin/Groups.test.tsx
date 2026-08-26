import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Groups } from './Groups'
import * as client from '../../api/client'
import { GRUPOS } from './admin.fixture'
import { elegir } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(grupos = GRUPOS, detalle?: Record<string, unknown>) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/groups/list') return ok({ response: { groups: grupos }, server: 'x' })
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

describe('Groups — la tabla', () => {
  it('pinta nombre, descripción y el total', async () => {
    servidor()
    render(<Groups {...props} />)
    expect(await screen.findByText('Super administrators')).toBeInTheDocument()
    expect(screen.getByText('Total Groups: 3')).toBeInTheDocument()
  })

  it('una descripción con saltos de línea se pinta en varias líneas', async () => {
    servidor([{ name: 'Ops', description: 'primera\nsegunda' }])
    render(<Groups {...props} />)
    expect(await screen.findByText('primera')).toBeInTheDocument()
    expect(screen.getByText('segunda')).toBeInTheDocument()
  })

  it('sin grupos el total dice cero', async () => {
    servidor([])
    render(<Groups {...props} />)
    expect(await screen.findByText('Total Groups: 0')).toBeInTheDocument()
  })

  it('si el servidor falla avisa con su mensaje', async () => {
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

describe('Groups — «Add Group»', () => {
  it('exige el nombre y nada más', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Add Group' }))
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByText('Please enter a name to add group.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/groups/create')).toBeUndefined()
  })

  it('crea el grupo con su descripción y lo pone el primero de la lista', async () => {
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

describe('Groups — el modal de detalles', () => {
  it('guarda miembros limpiados y SIN `newGroup` si el nombre no cambió', async () => {
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

  it('`newGroup` viaja cuando el nombre cambia', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click((await screen.findAllByRole('button', { name: 'View Details' }))[0])
    const nombre = await screen.findByLabelText('Name')
    await user.clear(nombre)
    await user.type(nombre, 'Otros')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const body = spy.mock.calls.find((c) => c[0] === 'admin/groups/set')?.[1]?.body as Record<string, string>
    expect(body.newGroup).toBe('Otros')
    expect(body.group).toBe('Administrators')
  })

  it('«Add User» añade al final y «None» vacía la lista de miembros', async () => {
    servidor()
    const user = userEvent.setup()
    render(<Groups {...props} />)

    await user.click((await screen.findAllByRole('button', { name: 'View Details' }))[0])
    const add = await screen.findByLabelText('Add User')

    await elegir(user, add, 'testuser')
    expect(screen.getByLabelText('Members')).toHaveValue('admin\ntestuser\n')

    await elegir(user, add, 'None')
    expect(screen.getByLabelText('Members')).toHaveValue('')
  })

  it('borrar pide confirmación con el nombre y saca la fila', async () => {
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
