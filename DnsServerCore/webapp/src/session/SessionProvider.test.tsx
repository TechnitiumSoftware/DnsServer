import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SessionProvider } from './SessionProvider'
import { ThemeProvider } from '../theme/ThemeProvider'
import * as client from '../api/client'

// El Shell consume el tema, así que se monta como lo hará App.tsx.
function montar() {
  return render(
    <ThemeProvider>
      <SessionProvider />
    </ThemeProvider>,
  )
}

function permisos(overrides: Record<string, boolean> = {}) {
  const secciones = ['Dashboard','Zones','Cache','Allowed','Blocked','Apps','DnsClient','Settings','DhcpServer','Administration','Logs']
  return Object.fromEntries(
    secciones.map((s) => [s, { canView: overrides[s] ?? true, canModify: true, canDelete: true }]),
  )
}

function sesion(extra: Record<string, unknown> = {}, permOverrides = {}) {
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
        permissions: permisos(permOverrides),
      },
      /* Las pantallas que se montan al recorrer las secciones piden lo suyo con
         el mismo simulador; sin un `response` vacío, `listZones` y compañía
         revientan con un rechazo no capturado que ensucia la salida. */
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
  it('sin token, muestra el login', async () => {
    montar()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
  })

  it('con token válido guardado, entra directo sin pasar por el login', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    expect(await screen.findByRole('navigation')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Login' })).not.toBeInTheDocument()
  })

  it('con token inválido, cae al login', async () => {
    localStorage.setItem('token', 'caducado')
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    montar()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
  })

  it('con #error del SSO, muestra el login y la alerta con ese texto', async () => {
    window.history.replaceState(null, '', '/#error=' + encodeURIComponent('SSO authentication failed. Please try again.'))
    montar()
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument()
    expect(screen.getByText('SSO authentication failed. Please try again.')).toBeInTheDocument()
  })

  it('pone el título del documento con el formato de upstream', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')
    await waitFor(() =>
      expect(document.title).toBe('dns.shlab.app - Technitium DNS Server v15.4'),
    )
  })

  it('oculta las secciones sin permiso de lectura', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion({}, { DhcpServer: false, Administration: false }))
    montar()
    await screen.findByRole('navigation')
    expect(screen.queryByRole('link', { name: 'DHCP' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Administration' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Zones' })).toBeInTheDocument()
  })

  it('aterriza en la primera sección visible cuando Dashboard no lo es', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion({}, { Dashboard: false }))
    montar()
    await screen.findByRole('navigation')
    expect(screen.queryByRole('link', { name: 'Dashboard' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Zones' })).toHaveAttribute('aria-current', 'page')
  })

  /*
  El panel lateral se declaraba `tablist` y no lo era.

  Venía de cuando la consola no tenía direcciones: doce `role="tab"` sobre un
  único panel. Con rutas reales eso dejó de ser cierto —la guía de ARIA dice que
  si activar el elemento lleva a otra URL es un enlace—, y encima las
  sub-secciones colgaban dentro del `tablist` como botones sueltos, que es un
  hijo que ese rol no admite. Estos dos casos fijan lo contrario: enlaces con
  destino de verdad, todos alcanzables con el tabulador, y un único
  `aria-current="page"`.
  */
  it('el panel lateral son enlaces de verdad, no pestañas', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')

    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
    expect(screen.queryByRole('tabpanel')).not.toBeInTheDocument()

    // Destino copiable y abrible en otra pestaña, no un `href="#"`.
    expect(screen.getByRole('link', { name: 'Zones' })).toHaveAttribute('href', '/zones/')

    // Nadie fuera del orden de tabulación: en un menú, `Tab` los recorre todos.
    for (const enlace of screen.getAllByRole('link')) {
      expect(enlace).not.toHaveAttribute('tabindex', '-1')
    }
  })

  it('la sub-sección activa es la única que dice ser la página actual', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')

    fireEvent.click(screen.getByRole('link', { name: 'Logs' }))
    // La sección abre por su primera sub, y es ELLA la página, no la sección.
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

  it('una sección con sub-secciones completa la dirección sin dejar rastro en el historial', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    window.history.replaceState(null, '', '/settings/')
    montar()
    await screen.findByRole('navigation')

    // Estar «en Settings» sin más es media página: la dirección se completa.
    await waitFor(() => expect(window.location.pathname).toBe('/settings/general/'))
    expect(screen.getByRole('link', { name: 'General' })).toHaveAttribute('aria-current', 'page')

    /*
    Y volver atrás a `/settings/` la vuelve a completar REEMPLAZANDO. Si
    empujara, la entrada nueva sería otra vez `/settings/general/` y el botón
    «atrás» quedaría atrapado: cada pulsación volvería al mismo sitio.

    Se espía el método y no `history.length`, que en jsdom no se mueve ni con
    `pushState` —contarla daba un verde con el fallo dentro—.
    */
    const empujar = vi.spyOn(window.history, 'pushState')
    window.history.replaceState(null, '', '/settings/')
    fireEvent.popState(window)
    await waitFor(() => expect(window.location.pathname).toBe('/settings/general/'))
    expect(empujar).not.toHaveBeenCalled()
  })

  it('a un usuario de SSO le oculta cambiar contraseña y configurar 2FA', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion({ isSsoUser: true }))
    montar()
    await screen.findByRole('navigation')
    await userEvent.click(screen.getByRole('button', { name: /Administrator/ }))
    expect(screen.queryByText('Change Password')).not.toBeInTheDocument()
    expect(screen.queryByText('Configure 2FA')).not.toBeInTheDocument()
    expect(screen.getByText('Logout')).toBeInTheDocument()
  })

  it('a un usuario normal se los muestra', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')
    await userEvent.click(screen.getByRole('button', { name: /Administrator/ }))
    expect(screen.getByText('Change Password')).toBeInTheDocument()
    expect(screen.getByText('Configure 2FA')).toBeInTheDocument()
  })
})
