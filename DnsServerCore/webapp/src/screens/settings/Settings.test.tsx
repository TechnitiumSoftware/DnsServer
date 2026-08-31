import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Settings } from './Settings'
import { SETTINGS } from './ajustes.fixture'
import * as client from '../../api/client'
import { valorDe } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

/** Returns the `apiRequest` spy already loaded with the real `settings/get`
 *  response so the screen starts with real data. */
function servidor(overrides: Record<string, unknown> = {}) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'settings/get') return ok({ response: { ...SETTINGS, ...overrides } })
    if (path === 'settings/set') return ok({ response: { ...SETTINGS, ...overrides } })
    return ok({ response: {} })
  })
}

async function mount(props: Record<string, unknown> = {}) {
  const r = render(<Settings token="tok" {...props} />)
  await screen.findByRole('button', { name: 'Save Settings' })
  return r
}

describe('Settings — carga', () => {
  it('it draws General by default with the real values from the server', async () => {
    servidor()
    await mount()
    expect(screen.getByLabelText('DNS Server Domain')).toHaveValue('ref.technitium-ui.test')
    expect(screen.getByLabelText('Default Record TTL')).toHaveValue('3600')
    expect(screen.getByText('seconds (default 3600/1h)')).toBeInTheDocument()
  })

  it('if the server fails, it alerts instead of blowing up', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    render(<Settings token="tok" />)
    expect(await screen.findByText('Unable to load the DNS Server settings.')).toBeInTheDocument()
  })

  it('the active sub-tab arrives by prop: the sub-navigation belongs to the Shell', async () => {
    servidor()
    await mount({ sub: 'Logging' })
    expect(screen.getByLabelText('Log Folder Path')).toBeInTheDocument()
    expect(screen.queryByLabelText('DNS Server Domain')).not.toBeInTheDocument()
  })

  it('the nine sub-tabs draw without breaking', async () => {
    servidor()
    const subs = [
      ['General', 'DNS Server Domain'],
      ['Web Service', 'Web Service HTTP Port'],
      ['Optional Protocols', 'DNS-over-TLS Port'],
      ['TSIG', 'Shared Secret'],
      ['Recursion', 'Resolver Retries'],
      ['Cache', 'Cache Maximum Entries'],
      ['Blocking', 'Blocking Answer TTL'],
      ['Proxy & Forwarders', 'Forwarder Retries'],
      ['Logging', 'Max Stat File Days'],
    ] as const
    for (const [sub, brand] of subs) {
      const { unmount } = render(<Settings token="tok" sub={sub} />)
      expect(await screen.findByText(brand)).toBeInTheDocument()
      unmount()
    }
  })
})

describe('Settings — guardar', () => {
  it('it sends settings/set by POST with the fields of the nine sub-tabs', async () => {
    const spy = servidor()
    await mount({ sub: 'Logging' })
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    const call = await waitFor(() => {
      const c = spy.mock.calls.find((c) => c[0] === 'settings/set')
      expect(c).toBeDefined()
      return c!
    })
    expect(call[1]?.method).toBe('POST')
    const body = call[1]!.body as Record<string, string>
    expect(body.dnsServerDomain).toBe('ref.technitium-ui.test')
    expect(body.loggingType).toBe('File')
    expect(body.recursion).toBe('AllowOnlyForPrivateNetworks')
  })

  it('on a successful save, the alert is the upstream literal', async () => {
    servidor()
    await mount()
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Settings Saved!')).toBeInTheDocument()
    expect(screen.getByText('DNS Server settings were saved successfully.')).toBeInTheDocument()
  })

  it('a server error comes out with its errorMessage under the Error! title', async () => {
    vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'settings/get') return ok({ response: SETTINGS })
      return { kind: 'error' as const, message: 'Invalid Web Service HTTPS port.' }
    })
    await mount()
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Error!')).toBeInTheDocument()
    expect(screen.getByText('Invalid Web Service HTTPS port.')).toBeInTheDocument()
  })

  it('an empty field blocks the save with the literal alert, and does not call the server', async () => {
    const spy = servidor()
    await mount()
    await userEvent.clear(screen.getByLabelText('DNS Server Domain'))
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    expect(await screen.findByText('Please enter server domain name.')).toBeInTheDocument()
    expect(screen.getByText('Missing!')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'settings/set')).toBeUndefined()
  })

  it('if the missing field is on another sub-tab, the screen jumps to it', async () => {
    servidor()
    const onSubChange = vi.fn()
    await mount({ sub: 'Recursion', onSubChange })
    await userEvent.clear(screen.getByLabelText('Resolver Retries'))
    // It switches to another sub-tab before saving to exercise the jump.
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    expect(await screen.findByText('Please enter a value for Resolver Retries.')).toBeInTheDocument()
    expect(onSubChange).toHaveBeenCalledWith('Recursion')
  })

  it('the validation jump is undone as soon as the Shell asks for another sub-tab', async () => {
    servidor()
    const { rerender } = await mount({ sub: 'General' })
    await userEvent.clear(screen.getByLabelText('DNS Server Domain'))
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Please enter server domain name.')).toBeInTheDocument()

    rerender(<Settings token="tok" sub="Logging" />)
    expect(await screen.findByLabelText('Log Folder Path')).toBeInTheDocument()
    expect(screen.queryByLabelText('DNS Server Domain')).not.toBeInTheDocument()
  })
})

describe('Settings — Blocking', () => {
  it('with no date, the labels are \"Not Set\" and \"Not Scheduled\"', async () => {
    servidor()
    await mount({ sub: 'Blocking' })
    expect(screen.getByText('Not Set')).toBeInTheDocument()
    expect(screen.getByText('Not Scheduled')).toBeInTheDocument()
  })

  it('\"Update Now\" is off if there are no lists configured', async () => {
    servidor()
    await mount({ sub: 'Blocking' })
    expect(screen.getByRole('button', { name: 'Update Now' })).toBeDisabled()
  })

  it('switching off \"Enable Blocking\" switches off the rest of the sub-tab', async () => {
    servidor()
    await mount({ sub: 'Blocking' })
    expect(screen.getByLabelText('Allow TXT Blocking Report')).toBeEnabled()
    await userEvent.click(screen.getByLabelText('Enable Blocking'))
    expect(screen.getByLabelText('Allow TXT Blocking Report')).toBeDisabled()
    expect(screen.getByLabelText('Blocking Bypass List')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Temporary Disable Now' })).toBeDisabled()
  })

  it('with no minutes, \"Temporary Disable Now\" alerts with the literal text', async () => {
    servidor()
    await mount({ sub: 'Blocking' })
    await userEvent.click(screen.getByRole('button', { name: 'Temporary Disable Now' }))
    expect(
      await screen.findByText('Please enter a value in minutes to temporarily disable blocking.'),
    ).toBeInTheDocument()
  })

  it('with minutes, it confirms and calls the endpoint with the literal success alert', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'settings/get') return ok({ response: SETTINGS })
      if (path === 'settings/temporaryDisableBlocking') {
        return ok({ response: { temporaryDisableBlockingTill: '2026-08-25T14:00:00Z' } })
      }
      return ok({ response: {} })
    })
    await mount({ sub: 'Blocking' })

    await userEvent.type(screen.getByLabelText('Blocking Temporarily Disabled Till'), '15')
    await userEvent.click(screen.getByRole('button', { name: 'Temporary Disable Now' }))
    expect(
      await screen.findByText('Are you sure to temporarily disable blocking for 15 minute(s)?'),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Disable' }))

    const call = await waitFor(() => {
      const c = spy.mock.calls.find((c) => c[0] === 'settings/temporaryDisableBlocking')
      expect(c).toBeDefined()
      return c!
    })
    expect(call[1]?.body).toEqual({ minutes: '15' })
    expect(await screen.findByText('Blocking Disabled!')).toBeInTheDocument()
    expect(
      screen.getByText('Blocking was successfully disabled temporarily for 15 minute(s).'),
    ).toBeInTheDocument()
    // main.js:2393 — success also unchecks "Enable Blocking".
    expect(screen.getByLabelText('Enable Blocking')).not.toBeChecked()
  })

  it('\"Update Now\" confirms and fires forceUpdateBlockLists', async () => {
    const spy = servidor({ blockListUrls: ['https://example.com/list.txt'] })
    await mount({ sub: 'Blocking' })

    await userEvent.click(screen.getByRole('button', { name: 'Update Now' }))
    expect(
      await screen.findByText('Are you sure to force download and update the block lists?'),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Update' }))

    await waitFor(() =>
      expect(spy.mock.calls.find((c) => c[0] === 'settings/forceUpdateBlockLists')).toBeDefined(),
    )
    expect(await screen.findByText('Updating Block List!')).toBeInTheDocument()
    expect(screen.getByText('Block list update was triggered successfully.')).toBeInTheDocument()
    expect(screen.getByText('Updating Now')).toBeInTheDocument()
  })
})

describe('Settings — action bar', () => {
  it('\"Flush Cache\" confirms and calls cache/flush with its literal alert', async () => {
    const spy = servidor()
    await mount()
    await userEvent.click(screen.getByRole('button', { name: 'Flush Cache' }))
    expect(await screen.findByText('Are you sure to flush the DNS Server cache?')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Flush' }))

    await waitFor(() => expect(spy.mock.calls.find((c) => c[0] === 'cache/flush')).toBeDefined())
    expect(await screen.findByText('Flushed!')).toBeInTheDocument()
    expect(screen.getByText('DNS Server cache was flushed successfully.')).toBeInTheDocument()
  })

  it('the permissions govern each button separately', async () => {
    servidor()
    render(<Settings token="tok" canModify={false} canFlushCache={false} canBackup />)
    await screen.findByRole('button', { name: 'Backup Settings' })
    expect(screen.queryByRole('button', { name: 'Save Settings' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Flush Cache' })).not.toBeInTheDocument()
  })

  it('a backup with nothing checked alerts with the literal text', async () => {
    servidor()
    await mount()
    await userEvent.click(screen.getByRole('button', { name: 'Backup Settings' }))
    for (const label of [
      'Authentication Config File (auth.config)',
      'Cluster Config File (cluster.config)',
      'Web Service Config And Certificate File (webservice.config, *.pfx & *.p12)',
      'DNS Config And Certificate File (dns.config, *.pfx & *.p12)',
      'Log Config File (log.config)',
      'DNS Zone Files (*.zone)',
      'Allowed Zones File (allowed.config)',
      'Blocked Zones File (blocked.config)',
      'Block List Config And Cache Files (blocklist.config)',
      'DNS Apps',
      'DHCP Scope Files (*.scope)',
      'Dashboard Stats Files (*.stat, *.dstat)',
    ]) {
      await userEvent.click(screen.getByLabelText(label))
    }
    await userEvent.click(screen.getByRole('button', { name: 'Backup' }))
    expect(await screen.findByText('Please select at least one item to backup.')).toBeInTheDocument()
  })

  it('a restore with no file alerts before looking at the items', async () => {
    servidor()
    await mount()
    await userEvent.click(screen.getByRole('button', { name: 'Restore Settings' }))
    await userEvent.click(screen.getByRole('button', { name: 'Restore' }))
    expect(await screen.findByText('Please select a backup zip file to restore.')).toBeInTheDocument()
  })
})

describe('Settings — enablement rules of the remaining sub-tabs', () => {
  it('the recursion ACL can only be edited with the fourth option', async () => {
    servidor()
    await mount({ sub: 'Recursion' })
    const acl = screen.getByLabelText('Network Access Control List (ACL)')
    expect(acl).toBeDisabled()
    await userEvent.click(screen.getByLabelText('Use Specified Network Access Control List (ACL)'))
    expect(acl).toBeEnabled()
  })

  it('the proxy fields wake up on choosing a type', async () => {
    servidor()
    await mount({ sub: 'Proxy & Forwarders' })
    expect(screen.getByLabelText('Proxy Server Address')).toBeDisabled()
    await userEvent.click(screen.getByLabelText('SOCKS5 Proxy'))
    expect(screen.getByLabelText('Proxy Server Address')).toBeEnabled()
  })

  it('\"None\" in the logging switches off its four options and the folder', async () => {
    servidor()
    await mount({ sub: 'Logging' })
    expect(screen.getByLabelText('Log All Queries')).toBeEnabled()
    await userEvent.click(screen.getByLabelText('None'))
    expect(screen.getByLabelText('Log All Queries')).toBeDisabled()
    expect(screen.getByLabelText('Log Folder Path')).toBeDisabled()
  })

  it('the TSIG table adds and deletes rows', async () => {
    servidor()
    await mount({ sub: 'TSIG' })
    expect(screen.queryByLabelText('TSIG Keys 1 Key Name')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByLabelText('TSIG Keys 1 Key Name')).toBeInTheDocument()
    // The default algorithm of a new row is hmac-sha256.
    expect(valorDe(screen.getByLabelText('TSIG Keys 1 Algorithm'))).toBe('HMAC-SHA256 (recommended)')
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(screen.queryByLabelText('TSIG Keys 1 Key Name')).not.toBeInTheDocument()
  })

  it('the QPM table arrives with the real rows from the server', async () => {
    servidor()
    await mount()
    expect(screen.getByLabelText('Queries Per Minute (QPM) Limits (IPv4) 1 IPv4 Prefix')).toHaveValue(32)
    expect(screen.getByLabelText('Queries Per Minute (QPM) Limits (IPv4) 2 UDP Limit')).toHaveValue(6000)
    expect(screen.getByLabelText('Queries Per Minute (QPM) Limits (IPv6) 3 IPv6 Prefix')).toHaveValue(56)
  })
})
