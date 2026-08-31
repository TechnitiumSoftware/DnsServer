import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Allowed, Blocked, Cache } from './Listas'
import * as api from '../../api/zonelists'
import type { NodoLista, RegistroDns } from '../../api/zonelists'

afterEach(() => vi.restoreAllMocks())

const OK = { kind: 'ok' as const, data: { status: 'ok' } }

const REG_CACHE: RegistroDns = {
  name: 'example.com',
  type: 'A',
  ttl: '218 (3m38s)',
  rData: { ipAddress: '172.66.147.243' },
  dnssecStatus: 'Secure',
  responseMetadata: {
    nameServer: '8.8.8.8',
    protocol: 'Udp',
    datagramSize: '179 bytes',
    roundTripTime: '43 ms',
  },
  lastUsedOn: '2026-08-25T19:58:26.0233416Z',
}

const REG_AUTH: RegistroDns = {
  name: 'example.org',
  type: 'NS',
  ttl: 14400,
  ttlString: '4h',
  disabled: false,
  rData: { nameServer: 'ns1.casa.test' },
  dnssecStatus: 'Unknown',
  lastUsedOn: '0001-01-01T00:00:00',
  lastModified: '0001-01-01T00:00:00',
  expiryTtl: 0,
  expiryTtlString: '0s',
}

function node(p: Partial<NodoLista> = {}): NodoLista {
  return { domain: '', zones: [], records: [], ...p }
}

/** Leaves `listarNodo` returning whatever node it is given, whichever list it is. */
function conNodo(...nodes: NodoLista[]) {
  const spy = vi.spyOn(api, 'listarNodo')
  for (const n of nodes) spy.mockResolvedValueOnce({ kind: 'ok', data: n })
  spy.mockResolvedValue({ kind: 'ok', data: nodes[nodes.length - 1] ?? node() })
  return spy
}

async function confirm(etiqueta: string) {
  const dialogo = await screen.findByRole('dialog')
  await userEvent.click(within(dialogo).getByRole('button', { name: etiqueta }))
}

describe('tree navigation', () => {
  it('it starts by asking for the root of its list', async () => {
    const spy = conNodo(node({ zones: ['com'] }))
    render(<Cache token="t" />)
    await screen.findByText('com')
    const call = spy.mock.calls.find((c) => c[0] === 'cache')
    expect(call?.[2]).toBe('')
  })

  it('each section asks for its own endpoint', async () => {
    const spy = conNodo(node())
    render(<Blocked token="t" />)
    await screen.findByRole('heading', { name: 'Blocked' })
    expect(spy.mock.calls[0][0]).toBe('blocked')
  })

  /* The server walks down the chain on its own when the node has a single child
     and no records: the domain to draw is the one it RETURNS, not the one asked for. */
  it('it obeys the domain the server returns, not the one asked for', async () => {
    conNodo(node(), node({ domain: 'example.org', zones: ['foo.example.org'], records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.type(await screen.findByLabelText('Domain'), 'org')
    await userEvent.click(screen.getByRole('button', { name: 'Browse' }))
    expect(await screen.findByText('foo.example.org')).toBeInTheDocument()
    expect(screen.getByText(/1 records at/)).toBeInTheDocument()
  })

  it('the Browse field navigates to the typed domain', async () => {
    const spy = conNodo(node(), node({ domain: 'casa.test' }))
    render(<Cache token="t" />)
    await userEvent.type(await screen.findByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Browse' }))
    expect(spy.mock.calls.some((c) => c[2] === 'casa.test')).toBe(true)
  })

  it('going up to the parent from the tree sends direction=up, like the [up] link', async () => {
    const spy = conNodo(node({ domain: 'a.casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'casa.test' }))
    const subida = spy.mock.calls.find((c) => c[2] === 'casa.test')
    expect(subida?.[3]).toBe('up')
  })

  it('it shows the error message from the server if the listing fails', async () => {
    vi.spyOn(api, 'listarNodo').mockResolvedValue({ kind: 'error', message: 'Access was denied.' })
    render(<Cache token="t" />)
    expect(await screen.findByText('Access was denied.')).toBeInTheDocument()
  })
})

describe('records table', () => {
  it('it draws each rData field instead of a JSON dump', async () => {
    conNodo(node({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    expect(await screen.findByText('IP Address')).toBeInTheDocument()
    expect(screen.getByText('172.66.147.243')).toBeInTheDocument()
  })

  it('it splits the TTL into a number and a human form', async () => {
    conNodo(node({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    expect(await screen.findByText('218')).toBeInTheDocument()
    expect(screen.getByText('(3m38s)')).toBeInTheDocument()
  })

  it('it keeps the response metadata on the grey line', async () => {
    conNodo(node({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    const meta = await screen.findByText(/via 8\.8\.8\.8/)
    expect(meta).toHaveTextContent('179 bytes')
    expect(meta).toHaveTextContent('43 ms')
    expect(meta).toHaveTextContent('used 2026-08-25 19:58')
  })

  it('the DNSSEC column belongs to Cache only', async () => {
    conNodo(node({ domain: 'example.com', records: [REG_CACHE] }))
    const { unmount } = render(<Cache token="t" />)
    expect(await screen.findByRole('columnheader', { name: 'DNSSEC' })).toBeInTheDocument()
    unmount()

    conNodo(node({ domain: 'example.org', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await screen.findByText('Name Server')
    expect(screen.queryByRole('columnheader', { name: 'DNSSEC' })).not.toBeInTheDocument()
    // But the DNSSEC state is not lost: it drops down to the grey line.
    expect(screen.getByText(/DNSSEC Unknown/)).toBeInTheDocument()
  })

  it('it explains the empty node instead of leaving a bare []', async () => {
    conNodo(node({ zones: ['com', 'net'] }))
    render(<Blocked token="t" />)
    expect(await screen.findByText('No records at this node')).toBeInTheDocument()
  })
})

describe('Cache', () => {
  it('Flush Cache confirms with the literal text of upstream', async () => {
    conNodo(node())
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush Cache' }))
    expect(
      await screen.findByText('Are you sure to flush the DNS Server cache?'),
    ).toBeInTheDocument()
  })

  it('flushing the cache alerts with the literal text and returns to the root', async () => {
    const spy = vi.spyOn(api, 'vaciarCache').mockResolvedValue(OK)
    const list = conNodo(node({ domain: 'casa.test', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush Cache' }))
    await confirm('Flush Cache')
    expect(spy).toHaveBeenCalled()
    expect(
      await screen.findByText('DNS Server cache was flushed successfully.'),
    ).toBeInTheDocument()
    expect(list.mock.calls[list.mock.calls.length - 1][2]).toBe('')
  })

  /* In cache the Delete button depends on the NODE, not on it having records
     (other-zones.js:143-152). In allowed and blocked it is the other way round. */
  it('Delete is absent at <ROOT> and present on a node, even one with no records', async () => {
    conNodo(node({ zones: ['com'] }))
    const { unmount } = render(<Cache token="t" />)
    await screen.findByText('com')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    unmount()

    conNodo(node({ domain: 'casa.test', zones: ['a.casa.test'], records: [] }))
    render(<Cache token="t" />)
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('deleting a node confirms and alerts with the literal texts', async () => {
    const spy = vi.spyOn(api, 'deleteCacheNode').mockResolvedValue(OK)
    conNodo(node({ domain: 'casa.test', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText(
        "Are you sure you want to delete the cached zone 'casa.test' and all its records?",
      ),
    ).toBeInTheDocument()
    await confirm('Delete')
    expect(spy.mock.calls[0][1]).toBe('casa.test')
    expect(
      await screen.findByText("Cached zone 'casa.test' was deleted successfully."),
    ).toBeInTheDocument()
  })
})

describe('Allowed', () => {
  it('it requires the domain with the literal text of upstream', async () => {
    conNodo(node())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Allow' }))
    expect(await screen.findByText('Please enter a domain name to allow.')).toBeInTheDocument()
  })

  it('it adds the domain, alerts with the literal text and empties the field', async () => {
    const spy = vi.spyOn(api, 'addDomain').mockResolvedValue(OK)
    conNodo(node())
    render(<Allowed token="t" />)
    const field = await screen.findByLabelText('Domain')
    await userEvent.type(field, 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }))
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(spy.mock.calls[0][2]).toBe('casa.test')
    expect(
      await screen.findByText("Domain 'casa.test' was added to Allowed Zone successfully."),
    ).toBeInTheDocument()
    expect(field).toHaveValue('')
  })

  /* Delete here depends on the node HAVING records (other-zones.js:319-327). */
  it('Delete only appears when the node has records', async () => {
    conNodo(node({ domain: 'casa.test', zones: ['a.casa.test'], records: [] }))
    const { unmount } = render(<Allowed token="t" />)
    await screen.findByText('a.casa.test')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    unmount()

    conNodo(node({ domain: 'casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('deleting alerts with \"deleted from Allowed Zone\", which is not the Blocked text', async () => {
    vi.spyOn(api, 'deleteDomain').mockResolvedValue(OK)
    conNodo(node({ domain: 'casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText("Are you sure you want to delete the allowed zone 'casa.test'?"),
    ).toBeInTheDocument()
    await confirm('Delete')
    expect(
      await screen.findByText("Domain 'casa.test' was deleted from Allowed Zone successfully."),
    ).toBeInTheDocument()
  })

  it('Flush confirms and alerts with the literal texts', async () => {
    const spy = vi.spyOn(api, 'vaciarLista').mockResolvedValue(OK)
    conNodo(node())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush' }))
    expect(
      await screen.findByText('Are you sure you want to flush the entire Allowed zone?'),
    ).toBeInTheDocument()
    await confirm('Flush')
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(await screen.findByText('Allowed zone was flushed successfully.')).toBeInTheDocument()
  })

  it('Export goes through the single-use token and alerts', async () => {
    const spy = vi.spyOn(api, 'exportarDominios').mockResolvedValue({ ok: true })
    conNodo(node())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Export' }))
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(await screen.findByText('Allowed zones were exported successfully.')).toBeInTheDocument()
  })

  it('Import requires content with the literal text, inside the modal itself', async () => {
    conNodo(node())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Import' }))
    const dialogo = await screen.findByRole('dialog')
    await userEvent.click(within(dialogo).getByRole('button', { name: 'Import' }))
    expect(
      await within(dialogo).findByText('Please enter allowed zones to import.'),
    ).toBeInTheDocument()
  })

  it('Import sends the cleaned list and alerts with the literal text', async () => {
    const spy = vi.spyOn(api, 'importarDominios').mockResolvedValue(OK)
    conNodo(node())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Import' }))
    const dialogo = await screen.findByRole('dialog')
    await userEvent.type(within(dialogo).getByLabelText('Allowed Zones'), 'a.test\n\nb.test')
    await userEvent.click(within(dialogo).getByRole('button', { name: 'Import' }))
    expect(spy.mock.calls[0][2]).toBe('a.test,b.test')
    expect(
      await screen.findByText('Domain names were imported into allowed zone successfully.'),
    ).toBeInTheDocument()
  })
})

describe('Blocked', () => {
  it('it requires the domain with its own literal text', async () => {
    conNodo(node())
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Block' }))
    expect(await screen.findByText('Please enter a domain name to block.')).toBeInTheDocument()
  })

  it('it alerts with \"added to Blocked Zone\"', async () => {
    vi.spyOn(api, 'addDomain').mockResolvedValue(OK)
    conNodo(node())
    render(<Blocked token="t" />)
    await userEvent.type(await screen.findByLabelText('Domain'), 'ads.test')
    await userEvent.click(screen.getByRole('button', { name: 'Block' }))
    expect(
      await screen.findByText("Domain 'ads.test' was added to Blocked Zone successfully."),
    ).toBeInTheDocument()
  })

  /* Upstream's asymmetry: Allowed says "Domain 'x' was deleted from Allowed
     Zone successfully." and Blocked says "Blocked zone 'x' was deleted
     successfully.". They are two different sentences and both are contract. */
  it('deleting alerts with \"Blocked zone ... was deleted successfully\"', async () => {
    vi.spyOn(api, 'deleteDomain').mockResolvedValue(OK)
    conNodo(node({ domain: 'ads.test', records: [REG_AUTH] }))
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText("Are you sure you want to delete the blocked zone 'ads.test'?"),
    ).toBeInTheDocument()
    await confirm('Delete')
    expect(
      await screen.findByText("Blocked zone 'ads.test' was deleted successfully."),
    ).toBeInTheDocument()
  })

  it('Flush and Import use the Blocked texts, not the Allowed ones', async () => {
    vi.spyOn(api, 'vaciarLista').mockResolvedValue(OK)
    conNodo(node())
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush' }))
    expect(
      await screen.findByText('Are you sure you want to flush the entire Blocked zone?'),
    ).toBeInTheDocument()
    await confirm('Flush')
    expect(await screen.findByText('Blocked zone was flushed successfully.')).toBeInTheDocument()
  })

  it('the Import modal is the Blocked one', async () => {
    vi.spyOn(api, 'importarDominios').mockResolvedValue(OK)
    conNodo(node())
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Import' }))
    const dialogo = await screen.findByRole('dialog')
    expect(within(dialogo).getByText('Import Blocked Zones')).toBeInTheDocument()
    await userEvent.type(within(dialogo).getByLabelText('Blocked Zones'), 'ads.test')
    await userEvent.click(within(dialogo).getByRole('button', { name: 'Import' }))
    expect(
      await screen.findByText('Domain names were imported into blocked zone successfully.'),
    ).toBeInTheDocument()
  })
})
