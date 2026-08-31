import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DnsClient } from './DnsClient'
import * as api from '../../api/dnsclient'

afterEach(() => vi.restoreAllMocks())

describe('DNS Client', () => {
  it('it requires the domain with the literal text of upstream', async () => {
    render(<DnsClient token="t" />)
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(await screen.findByText('Please enter a domain name to query.')).toBeInTheDocument()
  })

  it('it requires the server with the literal text, and before the domain', async () => {
    render(<DnsClient token="t" />)
    await userEvent.clear(screen.getByLabelText('Server'))
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(await screen.findByText('Please enter a valid Name Server.')).toBeInTheDocument()
  })

  it('Resolve does not import; Import does', async () => {
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

  it('on importing it confirms with the literal text', async () => {
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
  The second panel of upstream's accordion ("Raw Responses (N)",
  `dnsclient.js:178-194`) was missing entirely: the API type already declared
  `rawResponses` and nobody drew it. It is what lets you see what each server
  answered along the way when a recursive query goes wrong.
  */
  it('it shows the raw responses, collapsed and with their count', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { result: {}, rawResponses: [{ a: 1 }, { b: 2 }, { c: 3 }] } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))

    const summary = await screen.findByText('Raw Responses (3)')
    // Collapsed, as in upstream: the final answer is what gets looked at first.
    expect(summary.closest('details')).not.toHaveAttribute('open')
  })

  it('with no raw responses there is no panel to open', async () => {
    vi.spyOn(api, 'resolve').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { result: {}, rawResponses: [] } },
    } as never)
    render(<DnsClient token="t" />)
    await userEvent.type(screen.getByLabelText('Domain'), 'casa.test')
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    await screen.findByText('Response')
    expect(screen.queryByText(/Raw Responses/)).not.toBeInTheDocument()
  })

  it('a warningMessage from the server is shown as an alert and beats the imported one', async () => {
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
