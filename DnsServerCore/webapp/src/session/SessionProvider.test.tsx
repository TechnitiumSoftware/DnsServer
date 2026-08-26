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
    expect(screen.queryByRole('tab', { name: 'DHCP' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Administration' })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Zones' })).toBeInTheDocument()
  })

  it('aterriza en la primera sección visible cuando Dashboard no lo es', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion({}, { Dashboard: false }))
    montar()
    await screen.findByRole('navigation')
    expect(screen.queryByRole('tab', { name: 'Dashboard' })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Zones' })).toHaveAttribute('aria-selected', 'true')
  })

  /*
  El patrón de pestañas se declaraba y no se cumplía: doce `role="tab"` sin
  `tabpanel`, sin `aria-controls` y con las doce en el orden de tabulación.
  Upstream sí lo cumple (28 `role="tabpanel"`), así que faltaba de nuestro lado.
  */
  it('las pestañas gobiernan un panel y sólo la activa está en el orden de tabulación', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')

    const panel = screen.getByRole('tabpanel')
    const activa = screen.getByRole('tab', { name: 'Dashboard' })
    expect(activa).toHaveAttribute('aria-controls', panel.id)
    expect(panel).toHaveAttribute('aria-labelledby', activa.id)
    expect(activa).toHaveAttribute('tabindex', '0')
    expect(screen.getByRole('tab', { name: 'Zones' })).toHaveAttribute('tabindex', '-1')
  })

  it('las flechas recorren las secciones y dan la vuelta por los extremos', async () => {
    localStorage.setItem('token', 'tok')
    vi.spyOn(client, 'apiRequest').mockResolvedValue(sesion())
    montar()
    await screen.findByRole('navigation')

    const lista = screen.getByRole('tablist')
    const seleccionada = () =>
      screen.getAllByRole('tab').find((t) => t.getAttribute('aria-selected') === 'true')

    fireEvent.keyDown(lista, { key: 'ArrowDown' })
    await waitFor(() => expect(seleccionada()).toHaveAccessibleName('Zones'))

    fireEvent.keyDown(lista, { key: 'End' })
    await waitFor(() => expect(seleccionada()).toHaveAccessibleName('About'))

    // desde la última, «abajo» vuelve a la primera
    fireEvent.keyDown(lista, { key: 'ArrowDown' })
    await waitFor(() => expect(seleccionada()).toHaveAccessibleName('Dashboard'))

    // y desde la primera, «arriba» va a la última
    fireEvent.keyDown(lista, { key: 'ArrowUp' })
    await waitFor(() => expect(seleccionada()).toHaveAccessibleName('About'))

    fireEvent.keyDown(lista, { key: 'Home' })
    await waitFor(() => expect(seleccionada()).toHaveAccessibleName('Dashboard'))
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
