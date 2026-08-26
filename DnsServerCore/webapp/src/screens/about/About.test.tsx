import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { About } from './About'
import * as userApi from '../../api/user'

afterEach(() => vi.restoreAllMocks())

const info = { version: '15.4', uptimestamp: '2026-08-25T13:07:31Z', dnsServerDomain: 'dns.shlab.app' }

describe('About', () => {
  it('muestra versión, dominio y uptime', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    expect(screen.getByText('Version 15.4')).toBeInTheDocument()
    expect(screen.getByText('dns.shlab.app')).toBeInTheDocument()
  })

  it('respeta el aviso silenciado: no dice que estés al día si no lo ha mirado', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    expect(await screen.findByText('Update notifications are turned off for this server.')).toBeInTheDocument()
  })

  it('dice que estás al día cuando el servidor lo confirma', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { updateAvailable: false } },
    } as never)
    render(<About token="t" info={info} />)
    expect(await screen.findByText('No update available. You are running the latest version.')).toBeInTheDocument()
  })
})
