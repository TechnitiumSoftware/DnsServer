import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from '../../api/client'
import { Zones } from './Zones'

afterEach(() => vi.restoreAllMocks())

const ZONA = {
  name: 'casa.test',
  type: 'Primary',
  lastModified: '2026-08-26T10:00:00Z',
  disabled: false,
  soaSerial: 7,
  catalog: null,
  dnssecStatus: 'Unsigned',
  hasDnssecPrivateKeys: false,
  notifyFailed: false,
  notifyFailedFor: [],
}

const REGISTRO_A = {
  name: 'www.casa.test',
  type: 'A',
  ttl: 3600,
  ttlString: '1h',
  disabled: false,
  rData: { ipAddress: '10.0.0.1' },
  dnssecStatus: 'Unknown',
  lastUsedOn: '0001-01-01T00:00:00',
  lastModified: '2026-08-26T10:00:00Z',
  expiryTtl: 0,
  expiryTtlString: '',
}

/** Un servidor de mentira que responde por ruta. */
function servidor(respuestas: Record<string, unknown> = {}) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (ruta) => {
    const base = ruta.split('?')[0]
    if (base in respuestas) {
      return { kind: 'ok', data: { status: 'ok', response: respuestas[base] } } as never
    }
    if (base === 'zones/list') {
      return {
        kind: 'ok',
        data: { status: 'ok', response: { zones: [ZONA], pageNumber: 1, totalPages: 1, totalZones: 1 } },
      } as never
    }
    if (base === 'zones/records/get') {
      return {
        kind: 'ok',
        data: { status: 'ok', response: { zone: ZONA, records: [REGISTRO_A] } },
      } as never
    }
    return { kind: 'ok', data: { status: 'ok' } } as never
  })
}

function pintar(extra: Partial<Parameters<typeof Zones>[0]> = {}) {
  return render(<Zones token="t" canModify canDelete {...extra} />)
}

describe('lista de zonas', () => {
  it('pide la primera página y pinta la zona', async () => {
    const spy = servidor()
    pintar()

    expect(await screen.findByRole('button', { name: 'casa.test' })).toBeTruthy()
    const call = spy.mock.calls.find((c) => c[0] === 'zones/list')
    expect(call![1]?.body).toMatchObject({ pageNumber: '1', zonesPerPage: '10', node: '' })
  })

  it('sin zonas dice «No Zone Found»', async () => {
    servidor({ 'zones/list': { zones: [], pageNumber: 1, totalPages: 1, totalZones: 0 } })
    pintar()
    expect(await screen.findByText('No Zone Found')).toBeTruthy()
    // El estado se pinta arriba Y abajo de la tabla, como en upstream.
    expect(screen.getAllByText('0 zones')).toHaveLength(2)
  })

  it('los filtros NO recargan solos: hace falta pulsar «Go»', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    const llamadasIniciales = spy.mock.calls.filter((c) => c[0] === 'zones/list').length
    await usuario.type(screen.getByLabelText('Name'), 'ca')
    expect(spy.mock.calls.filter((c) => c[0] === 'zones/list')).toHaveLength(llamadasIniciales)

    await usuario.click(screen.getByRole('button', { name: 'Go' }))
    const ultima = spy.mock.calls.filter((c) => c[0] === 'zones/list').at(-1)
    expect(ultima![1]?.body).toMatchObject({ filterName: 'ca' })
  })

  it('«Delete Zones» sin marcar nada avisa en vez de llamar al servidor', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Delete Zones' }))
    expect(await screen.findByText('Please select one or more zones to delete.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => c[0] === 'zones/delete')).toBeUndefined()
  })

  it('deshabilitar una zona pregunta antes, con el texto de upstream', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Disable' }))
    expect(
      await screen.findByText("Are you sure you want to disable the zone 'casa.test'?"),
    ).toBeTruthy()
    expect(spy.mock.calls.find((c) => c[0] === 'zones/disable')).toBeUndefined()

    await usuario.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(spy.mock.calls.find((c) => c[0] === 'zones/disable')).toBeDefined())
    expect(await screen.findByText("Zone 'casa.test' was disabled successfully.")).toBeTruthy()
  })

  it('el borrado en bloque manda `zones` en plural, separadas por coma', async () => {
    const usuario = userEvent.setup()
    const spy = servidor({ 'zones/delete': { deleted: ['casa.test'], failed: {} } })
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByLabelText('Select casa.test'))
    await usuario.click(screen.getByRole('button', { name: 'Delete Zones' }))
    await usuario.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => c[0] === 'zones/delete')
      expect(call![1]?.body).toMatchObject({ zones: 'casa.test' })
    })
    expect(await screen.findByText('All selected zones were deleted successfully.')).toBeTruthy()
  })

  it('si alguna falla, el aviso es un warning con el recuento', async () => {
    const usuario = userEvent.setup()
    servidor({ 'zones/delete': { deleted: ['a.test'], failed: { 'b.test': 'nope' } } })
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByLabelText('Select casa.test'))
    await usuario.click(screen.getByRole('button', { name: 'Delete Zones' }))
    await usuario.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    expect(
      await screen.findByText(
        'A total of 1 zone(s) of the selected 2 zone(s) failed to delete. Please check error logs for more details.',
      ),
    ).toBeTruthy()
  })

  it('sin permiso de modificación no se puede añadir ni deshabilitar', async () => {
    servidor()
    pintar({ canModify: false })
    await screen.findByRole('button', { name: 'casa.test' })

    expect(screen.getByRole('button', { name: 'Add Zone' })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: 'Disable' })).toHaveProperty('disabled', true)
  })
})

describe('registros de una zona', () => {
  async function abrirZona() {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await usuario.click(await screen.findByRole('button', { name: 'casa.test' }))
    await screen.findByRole('heading', { name: 'casa.test' })
    return { usuario, spy }
  }

  it('pide la zona entera con listZone=true, sin paginar en el servidor', async () => {
    const { spy } = await abrirZona()
    const call = spy.mock.calls.find((c) => c[0] === 'zones/records/get')
    expect(call![1]?.body).toMatchObject({ listZone: 'true' })
    expect(call![1]?.body).not.toHaveProperty('recordsPerPage')
  })

  it('enseña el registro con su nombre relativo y su TTL', async () => {
    await abrirZona()
    expect(screen.getByText('www')).toBeTruthy()
    expect(screen.getByText('10.0.0.1')).toBeTruthy()
    expect(screen.getByText('(1h)')).toBeTruthy()
  })

  it('el filtro de nombre es exacto: «w» no encuentra «www»', async () => {
    const { usuario } = await abrirZona()
    await usuario.type(screen.getByLabelText('Name'), 'w')
    expect(await screen.findByText('No Record Found')).toBeTruthy()

    await usuario.type(screen.getByLabelText('Name'), 'ww')
    await waitFor(() => expect(screen.queryByText('No Record Found')).toBeNull())
  })

  it('borrar un registro pregunta y manda su identidad', async () => {
    const { usuario, spy } = await abrirZona()

    await usuario.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByText("Are you sure to permanently delete the A record 'www.casa.test'?")).toBeTruthy()

    await usuario.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await waitFor(() => {
      const call = spy.mock.calls.find((c) => String(c[0]).startsWith('zones/records/delete'))
      expect(call![1]?.body).toMatchObject({
        zone: 'casa.test',
        domain: 'www.casa.test',
        type: 'A',
        ipAddress: '10.0.0.1',
      })
    })
    expect(await screen.findByText('Resource record was deleted successfully.')).toBeTruthy()
  })

  it('deshabilitar un registro es un records/update con disable=true', async () => {
    const { usuario, spy } = await abrirZona()

    await usuario.click(screen.getByRole('button', { name: 'Disable' }))
    await usuario.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => String(c[0]).startsWith('zones/records/update'))
      expect(call![1]?.body).toMatchObject({ disable: 'true', type: 'A' })
    })
    expect(await screen.findByText('Resource record was disabled successfully.')).toBeTruthy()
  })

  it('una Primary sin firmar SÍ tiene menú DNSSEC, pero dentro sólo «Sign Zone»', async () => {
    // `divZoneDnssecOptions` se enseña para toda Primary; lo que cambia es lo
    // que hay dentro (zone.js:3374). Una Secondary sin firmar no lo enseña.
    const { usuario } = await abrirZona()
    await usuario.click(screen.getByRole('button', { name: 'DNSSEC actions' }))

    expect(await screen.findByRole('button', { name: 'Sign Zone' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Unsign Zone' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'View DS Info' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'DNSSEC Properties' })).toBeNull()
  })

  it('«← Zones» vuelve a la lista', async () => {
    const { usuario } = await abrirZona()
    await usuario.click(screen.getByRole('button', { name: '← Zones' }))
    expect(await screen.findByRole('heading', { name: 'Zones' })).toBeTruthy()
  })
})

describe('modales', () => {
  it('«Add Zone» valida el nombre antes de llamar al servidor', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Add Zone' }))
    await usuario.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Add' }))

    expect(await screen.findByText('Please enter a domain name to add zone.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => String(c[0]).startsWith('zones/create'))).toBeUndefined()
  })

  it('crear una zona Primary manda catalog y useSoaSerialDateScheme en la QUERY', async () => {
    const usuario = userEvent.setup()
    const spy = servidor({ 'zones/create': { domain: 'nueva.test' } })
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Add Zone' }))
    const dialogo = await screen.findByRole('dialog')
    await usuario.type(within(dialogo).getByLabelText('Zone'), 'nueva.test')
    await usuario.click(within(dialogo).getByRole('button', { name: 'Add' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => String(c[0]).startsWith('zones/create'))
      expect(String(call![0])).toContain('zone=nueva.test')
      expect(String(call![0])).toContain('useSoaSerialDateScheme=false')
      expect(call![1]?.method).toBe('POST')
    })
    // Upstream abre la zona recién creada.
    expect(await screen.findByRole('heading', { name: 'nueva.test' })).toBeTruthy()
  })

  it('«Convert Zone» de una Primary sólo deja convertir a Forwarder', async () => {
    const usuario = userEvent.setup()
    servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await usuario.click(await screen.findByRole('button', { name: 'Convert Zone' }))

    const dialogo = await screen.findByRole('dialog')
    expect(within(dialogo).getByLabelText('Primary Zone')).toHaveProperty('disabled', true)
    expect(within(dialogo).getByLabelText('Conditional Forwarder Zone')).toHaveProperty('checked', true)
    expect(within(dialogo).getByLabelText('Catalog Zone')).toHaveProperty('disabled', true)
  })

  it('«Import Zone» avisa si no se elige fichero', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await usuario.click(await screen.findByRole('button', { name: 'Import Zone' }))
    await usuario.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Import' }))

    expect(await screen.findByText('Please select a zone file to import.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => String(c[0]).startsWith('zones/import'))).toBeUndefined()
  })

  it('«Clone Zone» exige el nombre nuevo y manda zone y sourceZone', async () => {
    const usuario = userEvent.setup()
    const spy = servidor()
    pintar()
    await screen.findByRole('button', { name: 'casa.test' })

    await usuario.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await usuario.click(await screen.findByRole('button', { name: 'Clone Zone' }))

    const dialogo = await screen.findByRole('dialog')
    await usuario.click(within(dialogo).getByRole('button', { name: 'Clone Zone' }))
    expect(await screen.findByText('Please enter a domain name for the new zone.')).toBeTruthy()

    await usuario.type(within(dialogo).getByLabelText('New Zone'), 'copia.test')
    await usuario.click(within(dialogo).getByRole('button', { name: 'Clone Zone' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => c[0] === 'zones/clone')
      expect(call![1]?.body).toMatchObject({ zone: 'copia.test', sourceZone: 'casa.test' })
    })
  })
})
