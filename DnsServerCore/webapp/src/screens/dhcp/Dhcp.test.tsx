import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Dhcp } from './Dhcp'
import * as api from '../../api/dhcp'
import type { DhcpLease, DhcpScope, DhcpScopeRow } from '../../api/dhcp'

afterEach(() => vi.restoreAllMocks())

const DINAMICA: DhcpLease = {
  scope: 'Default',
  type: 'Dynamic',
  hardwareAddress: 'A4-83-E7-2B-19-0C',
  clientIdentifier: '1-A4-83-E7-2B-19-0C',
  address: '192.168.1.42',
  hostName: 'blackview-tab',
  leaseObtained: '2026-08-25T09:12:00Z',
  leaseExpires: '2026-08-26T09:12:00Z',
}

const RESERVADA: DhcpLease = {
  ...DINAMICA,
  type: 'Reserved',
  hardwareAddress: 'DC-A6-32-7F-44-81',
  clientIdentifier: '1-DC-A6-32-7F-44-81',
  address: '192.168.1.50',
  hostName: 'orbiter',
}

const SCOPE: DhcpScopeRow = {
  name: 'Default',
  enabled: true,
  startingAddress: '192.168.1.1',
  endingAddress: '192.168.1.254',
  subnetMask: '255.255.255.0',
  networkAddress: '192.168.1.0',
  broadcastAddress: '192.168.1.255',
}

const DETALLE: DhcpScope = {
  name: 'Default',
  startingAddress: '192.168.1.1',
  endingAddress: '192.168.1.254',
  subnetMask: '255.255.255.0',
  leaseTimeDays: 1,
  leaseTimeHours: 0,
  leaseTimeMinutes: 0,
  offerDelayTime: 0,
  pingCheckEnabled: false,
  pingCheckTimeout: 1000,
  pingCheckRetries: 2,
  domainName: 'home',
  dnsUpdates: true,
  dnsOverwriteForDynamicLease: false,
  dnsTtl: 900,
  routerAddress: '192.168.1.1',
  useThisDnsServer: true,
  dnsServers: ['172.23.0.2'],
  exclusions: [{ startingAddress: '192.168.1.1', endingAddress: '192.168.1.10' }],
  reservedLeases: [],
  allowOnlyReservedLeases: false,
  blockLocallyAdministeredMacAddresses: false,
  ignoreClientIdentifierOption: true,
}

const OK = { kind: 'ok' as const, data: {} }

function fila(nombre: string) {
  return within(screen.getByRole('row', { name: new RegExp(nombre) }))
}

describe('DHCP › Leases', () => {
  it('pinta una fila por concesión y el total al pie', async () => {
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA, RESERVADA] })
    render(<Dhcp token="t" sub="Leases" />)

    expect(await screen.findByText('192.168.1.42')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.50')).toBeInTheDocument()
    expect(screen.getByText('Total Leases: 2')).toBeInTheDocument()
  })

  /*
  El mensaje va DENTRO de la tabla y el pie sigue siendo el recuento.

  Antes el pie hacía de las dos cosas: con filas ponía el total y sin ellas el
  «No Lease Found», así que una tabla vacía dejaba el cuerpo en blanco bajo la
  banda de cabecera y el mensaje flotando fuera del panel. Upstream lo mete
  centrado en el pie de la propia tabla (`dhcp.js:74`) y el resto de la consola
  usa su fila de «no hay nada».
  */
  it('sin concesiones lo dice DENTRO de la tabla, y el pie sigue contando', async () => {
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [] })
    render(<Dhcp token="t" sub="Leases" />)

    const mensaje = await screen.findByText('No Lease Found')
    expect(mensaje.closest('table')).not.toBeNull()
    expect(screen.getByText('Total Leases: 0')).toBeInTheDocument()
  })

  it('cada fila ofrece sólo la conversión que le toca por su tipo', async () => {
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA, RESERVADA] })
    render(<Dhcp token="t" sub="Leases" />)
    await screen.findByText('192.168.1.42')

    expect(
      fila('192\\.168\\.1\\.42').getByRole('button', { name: 'Convert To Reserved Lease' }),
    ).toBeInTheDocument()
    expect(
      fila('192\\.168\\.1\\.42').queryByRole('button', { name: 'Convert To Dynamic Lease' }),
    ).not.toBeInTheDocument()

    expect(
      fila('192\\.168\\.1\\.50').getByRole('button', { name: 'Convert To Dynamic Lease' }),
    ).toBeInTheDocument()
  })

  it('reservar confirma, llama al endpoint con el clientIdentifier y avisa con el texto literal', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA] })
    const spy = vi.spyOn(api, 'convertToReservedLease').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Leases" />)
    await screen.findByText('192.168.1.42')

    await user.click(screen.getByRole('button', { name: 'Convert To Reserved Lease' }))
    expect(
      screen.getByText('Are you sure you want to convert the dynamic lease to reserved lease?'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Convert' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '1-A4-83-E7-2B-19-0C', '')
    expect(await screen.findByText('Reserved!')).toBeInTheDocument()
    expect(
      screen.getByText('The dynamic lease was converted to reserved lease successfully.'),
    ).toBeInTheDocument()
    // La fila cambia de tipo sin recargar: ahora ofrece la conversión inversa.
    expect(
      screen.getByRole('button', { name: 'Convert To Dynamic Lease' }),
    ).toBeInTheDocument()
  })

  it('desreservar avisa con «Unreserved!»', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [RESERVADA] })
    vi.spyOn(api, 'convertToDynamicLease').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Leases" />)
    await screen.findByText('192.168.1.50')

    await user.click(screen.getByRole('button', { name: 'Convert To Dynamic Lease' }))
    expect(
      screen.getByText('Are you sure you want to convert the reserved lease to dynamic lease?'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Convert' }))

    expect(await screen.findByText('Unreserved!')).toBeInTheDocument()
    expect(
      screen.getByText('The reserved lease was converted to dynamic lease successfully.'),
    ).toBeInTheDocument()
  })

  it('quitar una concesión abre el modal completo y la borra de la tabla', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA] })
    const spy = vi.spyOn(api, 'removeLease').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Leases" />)
    await screen.findByText('192.168.1.42')

    await user.click(screen.getByRole('button', { name: /^Actions for / }))
    await user.click(await screen.findByRole('button', { name: 'Remove Lease' }))
    expect(screen.getByText('Remove Lease?')).toBeInTheDocument()
    expect(
      screen.getByText('Are you sure you want to remove the DHCP lease now?'),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Remove' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '1-A4-83-E7-2B-19-0C', '')
    expect(await screen.findByText('Lease Removed!')).toBeInTheDocument()
    expect(screen.getByText('The DHCP lease was removed successfully.')).toBeInTheDocument()
    expect(screen.getByText('No Lease Found')).toBeInTheDocument()
  })

  it('si quitar falla, el aviso sale DENTRO del modal y la fila sigue ahí', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA] })
    vi.spyOn(api, 'removeLease').mockResolvedValue({ kind: 'error', message: 'DHCP scope does not exists: Default' })
    render(<Dhcp token="t" sub="Leases" />)
    await screen.findByText('192.168.1.42')

    await user.click(screen.getByRole('button', { name: /^Actions for / }))
    await user.click(await screen.findByRole('button', { name: 'Remove Lease' }))
    await user.click(screen.getByRole('button', { name: 'Remove' }))

    const modal = within(screen.getByRole('dialog'))
    expect(await modal.findByText('DHCP scope does not exists: Default')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.42')).toBeInTheDocument()
  })

  it('sin permiso de borrado no se ofrece quitar; sin permiso de modificación, ni convertir', async () => {
    vi.spyOn(api, 'listLeases').mockResolvedValue({ kind: 'ok', data: [DINAMICA] })
    render(<Dhcp token="t" sub="Leases" canModify={false} canDelete={false} />)
    await screen.findByText('192.168.1.42')

    expect(screen.queryByRole('button', { name: /^Actions for / })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Convert To Reserved Lease' }),
    ).not.toBeInTheDocument()
  })
})

describe('DHCP › Scopes', () => {
  it('pinta el rango, la red y el total al pie', async () => {
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    render(<Dhcp token="t" sub="Scopes" />)

    expect(await screen.findByText('Default')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.1 - 192.168.1.254')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.255')).toBeInTheDocument()
    expect(screen.getByText('Total Scopes: 1')).toBeInTheDocument()
  })

  it('sin scopes dice «No Scope Found»', async () => {
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    render(<Dhcp token="t" sub="Scopes" />)
    expect(await screen.findByText('No Scope Found')).toBeInTheDocument()
  })

  it('habilitar NO pregunta nada: llama al endpoint directamente', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [{ ...SCOPE, enabled: false }] })
    const spy = vi.spyOn(api, 'enableScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')

    await user.click(screen.getByRole('button', { name: 'Enable Scope' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '')
    expect(await screen.findByText('Scope Enabled!')).toBeInTheDocument()
    expect(screen.getByText('DHCP Scope was enabled successfully.')).toBeInTheDocument()
  })

  it('deshabilitar SÍ pregunta, con el nombre del scope en el texto', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    const spy = vi.spyOn(api, 'disableScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')

    await user.click(screen.getByRole('button', { name: 'Disable Scope' }))
    expect(
      screen.getByText("Are you sure you want to disable the DHCP scope 'Default'?"),
    ).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '')
    expect(await screen.findByText('Scope Disabled!')).toBeInTheDocument()
  })

  it('borrar pregunta y quita la fila sin recargar la lista', async () => {
    const user = userEvent.setup()
    const lista = vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    const spy = vi.spyOn(api, 'deleteScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')
    const llamadasIniciales = lista.mock.calls.length

    await user.click(screen.getByRole('button', { name: /^Actions for / }))
    await user.click(await screen.findByRole('button', { name: 'Delete Scope' }))
    expect(
      screen.getByText("Are you sure you want to delete the DHCP scope 'Default'?"),
    ).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '')
    expect(await screen.findByText('Scope Deleted!')).toBeInTheDocument()
    expect(screen.getByText('No Scope Found')).toBeInTheDocument()
    expect(lista.mock.calls).toHaveLength(llamadasIniciales)
  })

  it('sin permisos no salen ni «Add Scope», ni «Enable»/«Disable», ni «Delete»', async () => {
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    render(<Dhcp token="t" sub="Scopes" canModify={false} canDelete={false} />)
    await screen.findByText('Default')

    expect(screen.queryByRole('button', { name: 'Add Scope' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Disable Scope' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Actions for / })).not.toBeInTheDocument()
    // «Edit» sigue: sólo pide permiso de lectura.
    expect(screen.getByRole('button', { name: 'Edit Scope' })).toBeInTheDocument()
  })
})

describe('DHCP › Scopes — el formulario', () => {
  it('«Add Scope» abre el formulario vacío con «Use This DNS Server» marcado', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('No Scope Found')

    await user.click(screen.getByRole('button', { name: 'Add Scope' }))

    expect(screen.getByRole('heading', { name: 'Add Scope' })).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toHaveValue('')
    expect(screen.getByLabelText('Use This DNS Server')).toBeChecked()
    expect(screen.getByLabelText('DNS Servers')).toBeDisabled()
  })

  it('«Edit» carga el scope y rellena el formulario', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    const spy = vi.spyOn(api, 'getScope').mockResolvedValue(DETALLE)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')

    await user.click(screen.getByRole('button', { name: 'Edit Scope' }))

    expect(spy).toHaveBeenCalledWith('t', 'Default', '')
    expect(await screen.findByRole('heading', { name: 'Edit Scope' })).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toHaveValue('Default')
    expect(screen.getByLabelText('Domain Name')).toHaveValue('home')
    expect(screen.getByLabelText('Subnet Mask')).toHaveValue('255.255.255.0')
    expect(screen.getByLabelText('Exclusions 1 Starting Address')).toHaveValue('192.168.1.1')
  })

  it('«Enable DNS Updates» desmarcado deshabilita la casilla de sobrescritura', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('No Scope Found')
    await user.click(screen.getByRole('button', { name: 'Add Scope' }))

    const sobrescribir = screen.getByLabelText('Enable DNS Overwrite For Dynamic Lease')
    expect(sobrescribir).toBeEnabled()

    await user.click(screen.getByLabelText('Enable DNS Updates'))
    expect(sobrescribir).toBeDisabled()
  })

  it('guardar manda el cuerpo por POST y avisa con el texto literal', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    const spy = vi.spyOn(api, 'setScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('No Scope Found')

    await user.click(screen.getByRole('button', { name: 'Add Scope' }))
    await user.type(screen.getByLabelText('Name'), 'Casa')
    await user.type(screen.getByLabelText('Starting Address'), '10.0.1.1')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const [, body, node] = spy.mock.calls[0]
    expect(node).toBe('')
    expect(body).toMatchObject({ name: 'Casa', startingAddress: '10.0.1.1' })
    expect(body).not.toHaveProperty('newName')
    expect(await screen.findByText('Scope Saved!')).toBeInTheDocument()
    expect(screen.getByText('DHCP Scope was saved successfully.')).toBeInTheDocument()
  })

  it('cambiar el nombre de un scope existente manda el viejo en `name` y el nuevo en `newName`', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    vi.spyOn(api, 'getScope').mockResolvedValue(DETALLE)
    const spy = vi.spyOn(api, 'setScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')
    await user.click(screen.getByRole('button', { name: 'Edit Scope' }))
    await screen.findByRole('heading', { name: 'Edit Scope' })

    await user.clear(screen.getByLabelText('Name'))
    await user.type(screen.getByLabelText('Name'), 'Casa')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls[0][1]).toMatchObject({ name: 'Default', newName: 'Casa' })
  })

  it('una celda obligatoria vacía frena el guardado, avisa y enfoca esa celda', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    const spy = vi.spyOn(api, 'setScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('No Scope Found')
    await user.click(screen.getByRole('button', { name: 'Add Scope' }))

    // Una exclusión nueva nace con las dos celdas vacías.
    const anadir = screen.getAllByRole('button', { name: 'Add' })
    await user.click(anadir[3])
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy).not.toHaveBeenCalled()
    expect(screen.getByText('Missing!')).toBeInTheDocument()
    expect(
      screen.getByText('Please enter a valid value in the text field in focus.'),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Exclusions 1 Starting Address')).toHaveFocus()
  })

  it('un `|` en una celda da «Invalid Character!» con su texto literal', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [] })
    const spy = vi.spyOn(api, 'setScope').mockResolvedValue(OK)
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('No Scope Found')
    await user.click(screen.getByRole('button', { name: 'Add Scope' }))

    const anadir = screen.getAllByRole('button', { name: 'Add' })
    await user.click(anadir[3])
    await user.type(screen.getByLabelText('Exclusions 1 Starting Address'), 'a|b')
    await user.type(screen.getByLabelText('Exclusions 1 Ending Address'), '10.0.1.9')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy).not.toHaveBeenCalled()
    expect(screen.getByText('Invalid Character!')).toBeInTheDocument()
    expect(
      screen.getByText("Please edit the value in the text field in focus to remove '|' character."),
    ).toBeInTheDocument()
  })

  it('«Cancel» vuelve a la tabla y la recarga', async () => {
    const user = userEvent.setup()
    const lista = vi.spyOn(api, 'listScopes').mockResolvedValue({ kind: 'ok', data: [SCOPE] })
    render(<Dhcp token="t" sub="Scopes" />)
    await screen.findByText('Default')
    await user.click(screen.getByRole('button', { name: 'Add Scope' }))
    const antes = lista.mock.calls.length

    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(await screen.findByText('Total Scopes: 1')).toBeInTheDocument()
    expect(lista.mock.calls.length).toBeGreaterThan(antes)
  })
})
