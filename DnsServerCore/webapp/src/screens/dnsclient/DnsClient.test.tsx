import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DnsClient } from './DnsClient'
import * as api from '../../api/dnsclient'

afterEach(() => vi.restoreAllMocks())

describe('DNS Client', () => {
  it('exige el dominio con el texto literal de upstream', async () => {
    render(<DnsClient token="t" />)
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(await screen.findByText('Please enter a domain name to query.')).toBeInTheDocument()
  })

  it('exige el servidor con el texto literal, y antes que el dominio', async () => {
    render(<DnsClient token="t" />)
    await userEvent.clear(screen.getByLabelText('Server'))
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(await screen.findByText('Please enter a valid Name Server.')).toBeInTheDocument()
  })

  it('Resolve no importa; Import sí', async () => {
    const spy = vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { result: { ok: true } } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(spy.mock.calls[0][1].importar).toBeFalsy()
    spy.mockClear()
    await userEvent.click(screen.getByRole('button', { name: 'Import' }))
    expect(spy.mock.calls[0][1].importar).toBe(true)
  })

  it('al importar confirma con el texto literal', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { result: {} } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Import' }))
    expect(
      await screen.findByText('Resource records resolved by this DNS client query were successfully imported into this server.'),
    ).toBeInTheDocument()
  })

  /*
  El segundo panel del acordeón de upstream («Raw Responses (N)»,
  `dnsclient.js:178-194`) faltaba entero: el tipo de la API ya declaraba
  `rawResponses` y no lo pintaba nadie. Es lo que deja ver qué contestó cada
  servidor por el camino cuando una consulta recursiva sale mal.
  */
  it('enseña las respuestas en crudo, plegadas y con su recuento', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { result: {}, rawResponses: [{ a: 1 }, { b: 2 }, { c: 3 }] } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))

    const resumen = await screen.findByText('Raw Responses (3)')
    // Plegadas, como en upstream: la respuesta final es lo que se mira primero.
    expect(resumen.closest('details')).not.toHaveAttribute('open')
  })

  it('sin respuestas en crudo no hay panel que abrir', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { result: {}, rawResponses: [] } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    await screen.findByText('Response')
    expect(screen.queryByText(/Raw Responses/)).not.toBeInTheDocument()
  })

  it('un warningMessage del servidor se muestra como aviso y gana al de importado', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { result: {}, warningMessage: 'Ojo con esto' } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Import' }))
    expect(await screen.findByText('Ojo con esto')).toBeInTheDocument()
    expect(screen.queryByText(/successfully imported/)).not.toBeInTheDocument()
  })
})
