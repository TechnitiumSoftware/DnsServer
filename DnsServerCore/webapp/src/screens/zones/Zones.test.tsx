import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from '../../api/client'
import { Zones } from './Zones'

afterEach(() => vi.restoreAllMocks())

const ZONE = {
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

const A_RECORD = {
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

/** A fake server that answers by path. */
function servidor(respuestas: Record<string, unknown> = {}) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (route) => {
    const base = route.split('?')[0]
    if (base in respuestas) {
      return { kind: 'ok', data: { status: 'ok', response: respuestas[base] } } as never
    }
    if (base === 'zones/list') {
      return {
        kind: 'ok',
        data: { status: 'ok', response: { zones: [ZONE], pageNumber: 1, totalPages: 1, totalZones: 1 } },
      } as never
    }
    if (base === 'zones/records/get') {
      return {
        kind: 'ok',
        data: { status: 'ok', response: { zone: ZONE, records: [A_RECORD] } },
      } as never
    }
    return { kind: 'ok', data: { status: 'ok' } } as never
  })
}

function draw(extra: Partial<Parameters<typeof Zones>[0]> = {}) {
  return render(<Zones token="t" canModify canDelete {...extra} />)
}

describe('zone list', () => {
  it('it asks for the first page and draws the zone', async () => {
    const spy = servidor()
    draw()

    expect(await screen.findByRole('button', { name: 'casa.test' })).toBeTruthy()
    const call = spy.mock.calls.find((c) => c[0] === 'zones/list')
    expect(call![1]?.body).toMatchObject({ pageNumber: '1', zonesPerPage: '10', node: '' })
  })

  it('with no zones it says \"No Zone Found\"', async () => {
    servidor({ 'zones/list': { zones: [], pageNumber: 1, totalPages: 1, totalZones: 0 } })
    draw()
    expect(await screen.findByText('No Zone Found')).toBeTruthy()
    // The status is drawn above AND below the table, as in upstream.
    expect(screen.getAllByText('0 zones')).toHaveLength(2)
  })

  it('the filters do NOT reload on their own: \"Go\" has to be pressed', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    const llamadasIniciales = spy.mock.calls.filter((c) => c[0] === 'zones/list').length
    await user.type(screen.getByLabelText('Name'), 'ca')
    expect(spy.mock.calls.filter((c) => c[0] === 'zones/list')).toHaveLength(llamadasIniciales)

    await user.click(screen.getByRole('button', { name: 'Go' }))
    const last = spy.mock.calls.filter((c) => c[0] === 'zones/list').at(-1)
    expect(last![1]?.body).toMatchObject({ filterName: 'ca' })
  })

  it('\"Delete Zones\" with nothing checked alerts instead of calling the server', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Delete Zones' }))
    expect(await screen.findByText('Please select one or more zones to delete.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => c[0] === 'zones/delete')).toBeUndefined()
  })

  it('disabling a zone asks first, with the upstream text', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Disable Zone' }))
    expect(
      await screen.findByText("Are you sure you want to disable the zone 'casa.test'?"),
    ).toBeTruthy()
    expect(spy.mock.calls.find((c) => c[0] === 'zones/disable')).toBeUndefined()

    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(spy.mock.calls.find((c) => c[0] === 'zones/disable')).toBeDefined())
    expect(await screen.findByText("Zone 'casa.test' was disabled successfully.")).toBeTruthy()
  })

  it('delete lives in the row menu, not loose next to \"Disable\"', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    // In a row —one of two hundred and forty, with "Disable" next to it and no
    // undo anywhere— delete cannot sit one careless click away.
    expect(screen.queryByRole('button', { name: 'Delete Zone' })).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await user.click(await screen.findByRole('button', { name: 'Delete Zone' }))
    expect(
      await screen.findByText(
        "Are you sure you want to permanently delete the zone 'casa.test' and all its records?",
      ),
    ).toBeTruthy()
    expect(spy.mock.calls.find((c) => String(c[0]).startsWith('zones/delete'))).toBeUndefined()
  })

  it('the bulk delete sends `zones` in plural, comma-separated', async () => {
    const user = userEvent.setup()
    const spy = servidor({ 'zones/delete': { deleted: ['casa.test'], failed: {} } })
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByLabelText('Select casa.test'))
    await user.click(screen.getByRole('button', { name: 'Delete Zones' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => c[0] === 'zones/delete')
      expect(call![1]?.body).toMatchObject({ zones: 'casa.test' })
    })
    expect(await screen.findByText('All selected zones were deleted successfully.')).toBeTruthy()
  })

  it('if some fail, the alert is a warning with the count', async () => {
    const user = userEvent.setup()
    servidor({ 'zones/delete': { deleted: ['a.test'], failed: { 'b.test': 'nope' } } })
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByLabelText('Select casa.test'))
    await user.click(screen.getByRole('button', { name: 'Delete Zones' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))

    expect(
      await screen.findByText(
        'A total of 1 zone(s) of the selected 2 zone(s) failed to delete. Please check error logs for more details.',
      ),
    ).toBeTruthy()
  })

  it('without modify permission you can neither add nor disable', async () => {
    servidor()
    draw({ canModify: false })
    await screen.findByRole('button', { name: 'casa.test' })

    expect(screen.getByRole('button', { name: 'Add Zone' })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: 'Disable Zone' })).toHaveProperty('disabled', true)
  })
})

describe('records of a zone', () => {
  async function openZone() {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await user.click(await screen.findByRole('button', { name: 'casa.test' }))
    await screen.findByRole('heading', { name: 'casa.test' })
    return { user, spy }
  }

  it('it asks for the whole zone with listZone=true, without paginating on the server', async () => {
    const { spy } = await openZone()
    const call = spy.mock.calls.find((c) => c[0] === 'zones/records/get')
    expect(call![1]?.body).toMatchObject({ listZone: 'true' })
    expect(call![1]?.body).not.toHaveProperty('recordsPerPage')
  })

  it('it shows the record with its relative name and its TTL', async () => {
    await openZone()
    expect(screen.getByText('www')).toBeTruthy()
    expect(screen.getByText('10.0.0.1')).toBeTruthy()
    expect(screen.getByText('(1h)')).toBeTruthy()
  })

  it('the name filter is exact: \"w\" does not find \"www\"', async () => {
    const { user } = await openZone()
    await user.type(screen.getByLabelText('Name'), 'w')
    expect(await screen.findByText('No Record Found')).toBeTruthy()

    await user.type(screen.getByLabelText('Name'), 'ww')
    await waitFor(() => expect(screen.queryByText('No Record Found')).toBeNull())
  })

  it('deleting a record asks and sends its identity', async () => {
    const { user, spy } = await openZone()

    await user.click(screen.getByRole('button', { name: 'Actions for www A' }))
    await user.click(await screen.findByRole('button', { name: 'Delete Record' }))
    expect(await screen.findByText("Are you sure to permanently delete the A record 'www.casa.test'?")).toBeTruthy()

    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))
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

  it('disabling a record is a records/update with disable=true', async () => {
    const { user, spy } = await openZone()

    await user.click(screen.getByRole('button', { name: 'Disable Record' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => String(c[0]).startsWith('zones/records/update'))
      expect(call![1]?.body).toMatchObject({ disable: 'true', type: 'A' })
    })
    expect(await screen.findByText('Resource record was disabled successfully.')).toBeTruthy()
  })

  it('an unsigned Primary DOES have a DNSSEC menu, but inside only \"Sign Zone\"', async () => {
    // `divZoneDnssecOptions` is shown for every Primary; what changes is what is
    // inside it (zone.js:3374). An unsigned Secondary does not show it.
    const { user } = await openZone()
    await user.click(screen.getByRole('button', { name: 'DNSSEC actions' }))

    expect(await screen.findByRole('button', { name: 'Sign Zone' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Unsign Zone' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'View DS Info' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'DNSSEC Properties' })).toBeNull()
  })

  it('the path back leads to the list', async () => {
    const { user } = await openZone()
    // The "Zones" segment of the path IS the back button: before there was also a
    // «← Zones» suelto encima diciendo lo mismo.
    await user.click(within(screen.getByLabelText('Breadcrumb')).getByRole('button'))
    expect(await screen.findByRole('heading', { name: 'Zones' })).toBeTruthy()
  })
})

describe('modales', () => {
  it('\"Add Zone\" validates the name before calling the server', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Add Zone' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Add' }))

    expect(await screen.findByText('Please enter a domain name to add zone.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => String(c[0]).startsWith('zones/create'))).toBeUndefined()
  })

  it('creating a Primary zone sends catalog and useSoaSerialDateScheme in the QUERY', async () => {
    const user = userEvent.setup()
    const spy = servidor({ 'zones/create': { domain: 'nueva.test' } })
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Add Zone' }))
    const dialogo = await screen.findByRole('dialog')
    await user.type(within(dialogo).getByLabelText('Zone'), 'nueva.test')
    await user.click(within(dialogo).getByRole('button', { name: 'Add' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => String(c[0]).startsWith('zones/create'))
      expect(String(call![0])).toContain('zone=nueva.test')
      expect(String(call![0])).toContain('useSoaSerialDateScheme=false')
      expect(call![1]?.method).toBe('POST')
    })
    // Upstream opens the newly created zone.
    expect(await screen.findByRole('heading', { name: 'nueva.test' })).toBeTruthy()
  })

  it('\"Convert Zone\" on a Primary only allows converting to Forwarder', async () => {
    const user = userEvent.setup()
    servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await user.click(await screen.findByRole('button', { name: 'Convert Zone' }))

    const dialogo = await screen.findByRole('dialog')
    expect(within(dialogo).getByLabelText('Primary Zone')).toHaveProperty('disabled', true)
    expect(within(dialogo).getByLabelText('Conditional Forwarder Zone')).toHaveProperty('checked', true)
    expect(within(dialogo).getByLabelText('Catalog Zone')).toHaveProperty('disabled', true)
  })

  it('\"Import Zone\" alerts if no file is chosen', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await user.click(await screen.findByRole('button', { name: 'Import Zone' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Import' }))

    expect(await screen.findByText('Please select a zone file to import.')).toBeTruthy()
    expect(spy.mock.calls.find((c) => String(c[0]).startsWith('zones/import'))).toBeUndefined()
  })

  it('\"Clone Zone\" requires the new name and sends zone and sourceZone', async () => {
    const user = userEvent.setup()
    const spy = servidor()
    draw()
    await screen.findByRole('button', { name: 'casa.test' })

    await user.click(screen.getByRole('button', { name: 'Actions for casa.test' }))
    await user.click(await screen.findByRole('button', { name: 'Clone Zone' }))

    const dialogo = await screen.findByRole('dialog')
    await user.click(within(dialogo).getByRole('button', { name: 'Clone Zone' }))
    expect(await screen.findByText('Please enter a domain name for the new zone.')).toBeTruthy()

    await user.type(within(dialogo).getByLabelText('New Zone'), 'copia.test')
    await user.click(within(dialogo).getByRole('button', { name: 'Clone Zone' }))

    await waitFor(() => {
      const call = spy.mock.calls.find((c) => c[0] === 'zones/clone')
      expect(call![1]?.body).toMatchObject({ zone: 'copia.test', sourceZone: 'casa.test' })
    })
  })
})
