import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { About } from './About'
import * as userApi from '../../api/user'

afterEach(() => vi.restoreAllMocks())

const info = { version: '15.4', uptimestamp: '2026-08-25T13:07:31Z', dnsServerDomain: 'dns.shlab.app' }

describe('About', () => {
  it('it shows version, domain and uptime', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    expect(screen.getByText('Version 15.4')).toBeInTheDocument()
    expect(screen.getByText('dns.shlab.app')).toBeInTheDocument()
  })

  /*
  This screen's links are upstream's and they had been lost: of the original
  panel's nine, one survived. "Help Topics", "Support" and "Donate" were missing
  entirely, and the text still said "read the change log" without "change log"
  leading anywhere.

  This case pins them by DESTINATION and not by text: what must not happen again
  is the prose still being there and the destination not.
  */
  it('it keeps the nine destinations of the upstream panel', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    const destinos = new Set(
      screen.getAllByRole('link').map((a) => a.getAttribute('href')),
    )
    for (const esperado of [
      'https://go.technitium.com/?id=24', // GNU GPL v3.0
      'https://github.com/TechnitiumSoftware/DnsServer',
      'https://go.technitium.com/?id=23', // What's New / change log
      'https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md',
      'https://go.technitium.com/?id=25', // Help Topics
      'mailto:support@technitium.com',
      'https://mastodon.social/@technitium',
      'https://blog.technitium.com/',
      'https://www.reddit.com/r/technitium/',
      'https://go.technitium.com/?id=35', // Donate
    ]) {
      expect(destinos, `falta ${esperado}`).toContain(esperado)
    }
  })

  it('the external links open outside and without handing over the opener', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    for (const a of screen.getAllByRole('link')) {
      expect(a).toHaveAttribute('target', '_blank')
      expect(a.getAttribute('rel')).toContain('noreferrer')
    }
  })

  it('it honours the silenced notice: it does not say you are up to date if it never looked', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'skipped' })
    render(<About token="t" info={info} />)
    expect(await screen.findByText('Update notifications are turned off for this server.')).toBeInTheDocument()
  })

  /*
  "Notifications are switched off" is a claim about the server's configuration.
  Saying it when what happened is that the call fell over is not a nuance: it is
  answering on the server's behalf without having spoken to it.
  */
  it('a failure while checking is not reported as "notifications off"', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({ kind: 'error', message: 'boom' } as never)
    render(<About token="t" info={info} />)
    expect(await screen.findByText('Unable to check for updates.')).toBeInTheDocument()
    expect(
      screen.queryByText('Update notifications are turned off for this server.'),
    ).not.toBeInTheDocument()
  })

  it('it says you are up to date when the server confirms it', async () => {
    vi.spyOn(userApi, 'checkForUpdate').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { updateAvailable: false } },
    } as never)
    render(<About token="t" info={info} />)
    expect(await screen.findByText('No update available. You are running the latest version.')).toBeInTheDocument()
  })
})
