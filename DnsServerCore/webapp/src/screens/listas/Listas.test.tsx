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

function nodo(p: Partial<NodoLista> = {}): NodoLista {
  return { domain: '', zones: [], records: [], ...p }
}

/** Deja `listarNodo` devolviendo el nodo que se le pase, sea cual sea la lista. */
function conNodo(...nodos: NodoLista[]) {
  const spy = vi.spyOn(api, 'listarNodo')
  for (const n of nodos) spy.mockResolvedValueOnce({ kind: 'ok', data: n })
  spy.mockResolvedValue({ kind: 'ok', data: nodos[nodos.length - 1] ?? nodo() })
  return spy
}

async function confirmar(etiqueta: string) {
  const dialogo = await screen.findByRole('dialog')
  await userEvent.click(within(dialogo).getByRole('button', { name: etiqueta }))
}

describe('navegación del árbol', () => {
  it('arranca pidiendo la raíz de su lista', async () => {
    const spy = conNodo(nodo({ zones: ['com'] }))
    render(<Cache token="t" />)
    await screen.findByText('com')
    const llamada = spy.mock.calls.find((c) => c[0] === 'cache')
    expect(llamada?.[2]).toBe('')
  })

  it('cada sección pide su propio endpoint', async () => {
    const spy = conNodo(nodo())
    render(<Blocked token="t" />)
    await screen.findByRole('heading', { name: 'Blocked' })
    expect(spy.mock.calls[0][0]).toBe('blocked')
  })

  /* El servidor baja solo por la cadena cuando el nodo tiene un único hijo y
     ningún registro: hay que pintar el dominio QUE DEVUELVE, no el que se pidió. */
  it('obedece al dominio que devuelve el servidor, no al que se pidió', async () => {
    conNodo(nodo(), nodo({ domain: 'example.org', zones: ['foo.example.org'], records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.type(await screen.findByLabelText('Browse'), 'org')
    await userEvent.click(screen.getByRole('button', { name: 'Go' }))
    expect(await screen.findByText('foo.example.org')).toBeInTheDocument()
    expect(screen.getByText(/1 records at/)).toBeInTheDocument()
  })

  it('el campo Browse navega al dominio escrito', async () => {
    const spy = conNodo(nodo(), nodo({ domain: 'casa.test' }))
    render(<Cache token="t" />)
    await userEvent.type(await screen.findByLabelText('Browse'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Go' }))
    expect(spy.mock.calls.some((c) => c[2] === 'casa.test')).toBe(true)
  })

  it('subir al padre desde el árbol manda direction=up, como el enlace [up]', async () => {
    const spy = conNodo(nodo({ domain: 'a.casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'casa.test' }))
    const subida = spy.mock.calls.find((c) => c[2] === 'casa.test')
    expect(subida?.[3]).toBe('up')
  })

  it('muestra el mensaje de error del servidor si el listado falla', async () => {
    vi.spyOn(api, 'listarNodo').mockResolvedValue({ kind: 'error', message: 'Access was denied.' })
    render(<Cache token="t" />)
    expect(await screen.findByText('Access was denied.')).toBeInTheDocument()
  })
})

describe('tabla de registros', () => {
  it('pinta cada campo de rData en vez de un volcado JSON', async () => {
    conNodo(nodo({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    expect(await screen.findByText('IP Address')).toBeInTheDocument()
    expect(screen.getByText('172.66.147.243')).toBeInTheDocument()
  })

  it('parte el TTL en número y forma humana', async () => {
    conNodo(nodo({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    expect(await screen.findByText('218')).toBeInTheDocument()
    expect(screen.getByText('(3m38s)')).toBeInTheDocument()
  })

  it('conserva los metadatos de respuesta en la línea gris', async () => {
    conNodo(nodo({ domain: 'example.com', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    const meta = await screen.findByText(/vía 8\.8\.8\.8/)
    expect(meta).toHaveTextContent('179 bytes')
    expect(meta).toHaveTextContent('43 ms')
    expect(meta).toHaveTextContent('usado 2026-08-25 19:58')
  })

  it('la columna DNSSEC es sólo de Cache', async () => {
    conNodo(nodo({ domain: 'example.com', records: [REG_CACHE] }))
    const { unmount } = render(<Cache token="t" />)
    expect(await screen.findByRole('columnheader', { name: 'DNSSEC' })).toBeInTheDocument()
    unmount()

    conNodo(nodo({ domain: 'example.org', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await screen.findByText('Name Server')
    expect(screen.queryByRole('columnheader', { name: 'DNSSEC' })).not.toBeInTheDocument()
    // Pero el estado DNSSEC no se pierde: baja a la línea gris.
    expect(screen.getByText(/DNSSEC Unknown/)).toBeInTheDocument()
  })

  it('explica el nodo vacío en vez de dejar un [] suelto', async () => {
    conNodo(nodo({ zones: ['com', 'net'] }))
    render(<Blocked token="t" />)
    expect(await screen.findByText('No records at this node')).toBeInTheDocument()
  })
})

describe('Cache', () => {
  it('Flush Cache confirma con el texto literal de upstream', async () => {
    conNodo(nodo())
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush Cache' }))
    expect(
      await screen.findByText('Are you sure to flush the DNS Server cache?'),
    ).toBeInTheDocument()
  })

  it('al vaciar la cache avisa con el texto literal y vuelve a la raíz', async () => {
    const spy = vi.spyOn(api, 'vaciarCache').mockResolvedValue(OK)
    const lista = conNodo(nodo({ domain: 'casa.test', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush Cache' }))
    await confirmar('Flush Cache')
    expect(spy).toHaveBeenCalled()
    expect(
      await screen.findByText('DNS Server cache was flushed successfully.'),
    ).toBeInTheDocument()
    expect(lista.mock.calls[lista.mock.calls.length - 1][2]).toBe('')
  })

  /* En cache el botón Delete depende del NODO, no de que tenga registros
     (other-zones.js:143-152). En allowed y blocked es al revés. */
  it('Delete no está en <ROOT> y sí en un nodo, aunque el nodo no tenga registros', async () => {
    conNodo(nodo({ zones: ['com'] }))
    const { unmount } = render(<Cache token="t" />)
    await screen.findByText('com')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    unmount()

    conNodo(nodo({ domain: 'casa.test', zones: ['a.casa.test'], records: [] }))
    render(<Cache token="t" />)
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('borrar un nodo confirma y avisa con los textos literales', async () => {
    const spy = vi.spyOn(api, 'borrarNodoCache').mockResolvedValue(OK)
    conNodo(nodo({ domain: 'casa.test', records: [REG_CACHE] }))
    render(<Cache token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText(
        "Are you sure you want to delete the cached zone 'casa.test' and all its records?",
      ),
    ).toBeInTheDocument()
    await confirmar('Delete')
    expect(spy.mock.calls[0][1]).toBe('casa.test')
    expect(
      await screen.findByText("Cached zone 'casa.test' was deleted successfully."),
    ).toBeInTheDocument()
  })
})

describe('Allowed', () => {
  it('exige el dominio con el texto literal de upstream', async () => {
    conNodo(nodo())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Allow' }))
    expect(await screen.findByText('Please enter a domain name to allow.')).toBeInTheDocument()
  })

  it('añade el dominio, avisa con el texto literal y vacía el campo', async () => {
    const spy = vi.spyOn(api, 'anadirDominio').mockResolvedValue(OK)
    conNodo(nodo())
    render(<Allowed token="t" />)
    const campo = await screen.findByLabelText('Browse')
    await userEvent.type(campo, 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }))
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(spy.mock.calls[0][2]).toBe('casa.test')
    expect(
      await screen.findByText("Domain 'casa.test' was added to Allowed Zone successfully."),
    ).toBeInTheDocument()
    expect(campo).toHaveValue('')
  })

  /* Delete aquí depende de que el nodo TENGA registros (other-zones.js:319-327). */
  it('Delete sólo aparece cuando el nodo tiene registros', async () => {
    conNodo(nodo({ domain: 'casa.test', zones: ['a.casa.test'], records: [] }))
    const { unmount } = render(<Allowed token="t" />)
    await screen.findByText('a.casa.test')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    unmount()

    conNodo(nodo({ domain: 'casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('borrar avisa con «deleted from Allowed Zone», que no es el texto de Blocked', async () => {
    vi.spyOn(api, 'borrarDominio').mockResolvedValue(OK)
    conNodo(nodo({ domain: 'casa.test', records: [REG_AUTH] }))
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText("Are you sure you want to delete the allowed zone 'casa.test'?"),
    ).toBeInTheDocument()
    await confirmar('Delete')
    expect(
      await screen.findByText("Domain 'casa.test' was deleted from Allowed Zone successfully."),
    ).toBeInTheDocument()
  })

  it('Flush confirma y avisa con los textos literales', async () => {
    const spy = vi.spyOn(api, 'vaciarLista').mockResolvedValue(OK)
    conNodo(nodo())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush' }))
    expect(
      await screen.findByText('Are you sure you want to flush the entire Allowed zone?'),
    ).toBeInTheDocument()
    await confirmar('Flush')
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(await screen.findByText('Allowed zone was flushed successfully.')).toBeInTheDocument()
  })

  it('Export pasa por el token de un solo uso y avisa', async () => {
    const spy = vi.spyOn(api, 'exportarDominios').mockResolvedValue({ ok: true })
    conNodo(nodo())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Export' }))
    expect(spy.mock.calls[0][0]).toBe('allowed')
    expect(await screen.findByText('Allowed zones were exported successfully.')).toBeInTheDocument()
  })

  it('Import exige contenido con el texto literal, dentro del propio modal', async () => {
    conNodo(nodo())
    render(<Allowed token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Import' }))
    const dialogo = await screen.findByRole('dialog')
    await userEvent.click(within(dialogo).getByRole('button', { name: 'Import' }))
    expect(
      await within(dialogo).findByText('Please enter allowed zones to import.'),
    ).toBeInTheDocument()
  })

  it('Import manda la lista limpia y avisa con el texto literal', async () => {
    const spy = vi.spyOn(api, 'importarDominios').mockResolvedValue(OK)
    conNodo(nodo())
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
  it('exige el dominio con su propio texto literal', async () => {
    conNodo(nodo())
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Block' }))
    expect(await screen.findByText('Please enter a domain name to block.')).toBeInTheDocument()
  })

  it('avisa con «added to Blocked Zone»', async () => {
    vi.spyOn(api, 'anadirDominio').mockResolvedValue(OK)
    conNodo(nodo())
    render(<Blocked token="t" />)
    await userEvent.type(await screen.findByLabelText('Browse'), 'ads.test')
    await userEvent.click(screen.getByRole('button', { name: 'Block' }))
    expect(
      await screen.findByText("Domain 'ads.test' was added to Blocked Zone successfully."),
    ).toBeInTheDocument()
  })

  /* La asimetría de upstream: Allowed dice «Domain 'x' was deleted from Allowed
     Zone successfully.» y Blocked dice «Blocked zone 'x' was deleted
     successfully.». Son dos frases distintas y las dos son contrato. */
  it('borrar avisa con «Blocked zone ... was deleted successfully»', async () => {
    vi.spyOn(api, 'borrarDominio').mockResolvedValue(OK)
    conNodo(nodo({ domain: 'ads.test', records: [REG_AUTH] }))
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(
      await screen.findByText("Are you sure you want to delete the blocked zone 'ads.test'?"),
    ).toBeInTheDocument()
    await confirmar('Delete')
    expect(
      await screen.findByText("Blocked zone 'ads.test' was deleted successfully."),
    ).toBeInTheDocument()
  })

  it('Flush y Import usan los textos de Blocked, no los de Allowed', async () => {
    vi.spyOn(api, 'vaciarLista').mockResolvedValue(OK)
    conNodo(nodo())
    render(<Blocked token="t" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Flush' }))
    expect(
      await screen.findByText('Are you sure you want to flush the entire Blocked zone?'),
    ).toBeInTheDocument()
    await confirmar('Flush')
    expect(await screen.findByText('Blocked zone was flushed successfully.')).toBeInTheDocument()
  })

  it('el modal de Import es el de Blocked', async () => {
    vi.spyOn(api, 'importarDominios').mockResolvedValue(OK)
    conNodo(nodo())
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
