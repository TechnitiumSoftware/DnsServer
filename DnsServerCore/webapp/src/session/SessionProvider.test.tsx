import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SessionProvider } from './SessionProvider'
import { ThemeProvider } from '../theme/ThemeProvider'
import * as client from '../api/client'

// The Shell consumes the theme, so it is mounted the way App.tsx will.
function mount() {
  return render(
    <ThemeProvider>
      <SessionProvider />
    </ThemeProvider>,
  )
}

function permissions(overrides: Record<string, boolean> = {}) {
  const secciones = ['Dashboard','Zones','Cache','Allowed','Blocked','Apps','DnsClient','Settings','DhcpServer','Administration','Logs']
  return Object.fromEntries(
    secciones.map((s) => [s, { canView: overrides[s] ?? true, canModify: true, canDelete: true }]),
  )
}

function session(extra: Record<string, unknown> = {}, permOverrides = {}) {
  return {
    kind: 'ok' as const,
    data: {
      status: 'ok',
      token: 'tok',
      displayName: 'Administrator',
      username: 'admin',
      isSsoUser: false,
      totpEnabled: false,
      info: {
        version: '15.4',
        uptimestamp: '2026-08-25T13:07:31Z',
        dnsServerDomain: 'dns.shlab.app',
        permissions: permissions(permOverrides),
      },
      /* The screens mounted while walking the sections ask for their own things
         through the same mock; without an empty `response`, `listZones` and
         friends blow up with an uncaught rejection that dirties the output. */
      response: {},
      ...extra,
    },
  }
}

beforeEach(() => {
  localStorage.clear()
  window.history.replaceState(null, '', '/')
  document.cookie = 'token=; max-age=0; path=/'
})
afterEach(() => vi.restoreAllMocks())

describe('SessionProvider', () => {
  it('with no token, it shows the login', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
  })

  it('with a valid stored token, it goes straight in without the login', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    expect(await screen.findByRole('navigation')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Login' })).not.toBeInTheDocument()
  })

  it('with an invalid token, it falls back to the login', async () => {
    localStorage.setItem('token', 'caducado')
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    mount()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
  })

  it('with an SSO #error, it shows the login and the alert with that text', async () => {
    window.history.replaceState(null, '', '/#error=' + encodeURIComponent('SSO authentication failed. Please try again.'))
    mount()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
    expect(screen.getByText('SSO authentication failed. Please try again.')).toBeInTheDocument()
  })

  it('it sets the document title in the upstream format', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')
    await waitFor(() =>
      expect(document.title).toBe('dns.shlab.app - Technitium DNS Server v15.4'),
    )
  })

  it('it hides the sections with no read permission', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session({}, { DhcpServer: false, Administration: false }))
    mount()
    await screen.findByRole('navigation')
    expect(screen.queryByRole('link', { name: 'DHCP' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Administration' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Zones' })).toBeInTheDocument()
  })

  it('it lands on the first visible section when Dashboard is not one', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session({}, { Dashboard: false }))
    mount()
    await screen.findByRole('navigation')
    expect(screen.queryByRole('link', { name: 'Dashboard' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Zones' })).toHaveAttribute('aria-current', 'page')
  })

  /*
  The side panel declared itself a `tablist` and was not one.

  It came from when the console had no addresses: twelve `role="tab"` over a
  single panel. With real routes that stopped being true —the ARIA guidance says
  that if activating the element leads to another URL it is a link— and on top of
  that the sub-sections hung inside the `tablist` as loose buttons, a child that
  role does not allow. These two cases pin the opposite: links with a real
  destination, all of them reachable with the tab key, and a single
  `aria-current="page"`.
  */
  it('the side panel is real links, not tabs', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')

    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
    expect(screen.queryByRole('tabpanel')).not.toBeInTheDocument()

    // A destination that can be copied and opened in another tab, not an `href="#"`.
    expect(screen.getByRole('link', { name: 'Zones' })).toHaveAttribute('href', '/zones/')

    // Nobody outside the tab order: in a menu, `Tab` walks through them all.
    for (const link of screen.getAllByRole('link')) {
      expect(link).not.toHaveAttribute('tabindex', '-1')
    }
  })

  it('the active sub-section is the only one claiming to be the current page', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')

    fireEvent.click(screen.getByRole('link', { name: 'Logs' }))
    // The section opens on its first sub, and IT is the page, not the section.
    await waitFor(() =>
      expect(screen.getByRole('link', { name: 'View Logs' })).toHaveAttribute('aria-current', 'page'),
    )
    expect(screen.getByRole('link', { name: 'Logs' })).not.toHaveAttribute('aria-current')

    fireEvent.click(screen.getByRole('link', { name: 'Query Logs' }))
    await waitFor(() => expect(window.location.pathname).toBe('/logs/query-logs/'))

    const actuales = screen
      .getAllByRole('link')
      .filter((a) => a.getAttribute('aria-current') === 'page')
    expect(actuales.map((a) => a.textContent)).toEqual(['Query Logs'])
  })

  it('a section with sub-sections completes the address without leaving a trace in the history', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    window.history.replaceState(null, '', '/settings/')
    mount()
    await screen.findByRole('navigation')

    // Being "in Settings" and nothing more is half a page: the address is completed.
    await waitFor(() => expect(window.location.pathname).toBe('/settings/general/'))
    expect(screen.getByRole('link', { name: 'General' })).toHaveAttribute('aria-current', 'page')

    /*
    And going back to `/settings/` completes it again by REPLACING. If it
    pushed, the new entry would be `/settings/general/` all over again and the
    "back" button would be trapped: every press would return to the same place.

    The method is spied on and not `history.length`, which in jsdom does not
    budge even with `pushState` —counting it gave a green with the bug inside.
    */
    const empujar = vi.spyOn(window.history, 'pushState')
    window.history.replaceState(null, '', '/settings/')
    fireEvent.popState(window)
    await waitFor(() => expect(window.location.pathname).toBe('/settings/general/'))
    expect(empujar).not.toHaveBeenCalled()
  })

  it('the upstream footer is still there with the console open, not only on the login', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')
    // In upstream the footer hangs off the `body`: it shows on EVERY screen.
    expect(screen.getByRole('link', { name: 'Donate' })).toHaveAttribute(
      'href', 'https://go.technitium.com/?id=35',
    )
    /* "DNS Client" is also a section of the panel, so here it is found by the
       disambiguated name; see `app/pie.ts`. */
    expect(screen.getByRole('link', { name: 'DNS Client at dnsclient.net' })).toHaveAttribute(
      'href', 'https://dnsclient.net/',
    )
  })

  /*
  An expired session ends the session, as in upstream.

  Before, nobody did: every screen showed "Invalid token or session expired." and
  the console stayed standing, with every action failing one after another and no
  way back in short of reloading blindly. Upstream calls `showPageLogin()` —it
  clears the token and shows the login— in the sixty-four calls that declare the
  handler, and in the ones that do not, it falls through to the
  `window.location = "/"` of `common.js:147`.

  It is tested along the real path: `apiRequest` unmocked, with `fetch` answering
  what the server would answer. Mocking `apiRequest` would test nothing, because
  it is the one that emits the notice.
  */
  it('if the server rejects the session, the session ends and it returns to the login', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')

    // From here on, the server says the token is no longer valid.
    vi.restoreAllMocks()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ status: 'invalid-token' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await client.apiRequest('zones/list', { token: 'tok' })

    expect(await screen.findByLabelText('Password')).toBeInTheDocument()
    expect(localStorage.getItem('token')).toBeNull()
    expect(screen.getByText('Session expired. Please login again.')).toBeInTheDocument()
  })

  it('for an SSO user it hides changing the password and configuring 2FA', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session({ isSsoUser: true }))
    mount()
    await screen.findByRole('navigation')
    await userEvent.click(screen.getByRole('button', { name: /Administrator/ }))
    expect(screen.queryByText('Change Password')).not.toBeInTheDocument()
    expect(screen.queryByText('Configure 2FA')).not.toBeInTheDocument()
    expect(screen.getByText('Logout')).toBeInTheDocument()
  })

  it('for an ordinary user it shows them', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(session())
    mount()
    await screen.findByRole('navigation')
    await userEvent.click(screen.getByRole('button', { name: /Administrator/ }))
    expect(screen.getByText('Change Password')).toBeInTheDocument()
    expect(screen.getByText('Configure 2FA')).toBeInTheDocument()
  })
})
