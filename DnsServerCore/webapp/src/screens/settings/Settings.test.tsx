import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Settings } from './Settings'
import { AJUSTES } from './ajustes.fixture'
import * as client from '../../api/client'
import { valorDe } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

/** Devuelve el espía de `apiRequest` ya cargado con la respuesta real de
 *  `settings/get` para que la pantalla arranque con datos de verdad. */
function servidor(overrides: Record<string, unknown> = {}) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'settings/get') return ok({ response: { ...AJUSTES, ...overrides } })
    if (path === 'settings/set') return ok({ response: { ...AJUSTES, ...overrides } })
    return ok({ response: {} })
  })
}

async function montar(props: Record<string, unknown> = {}) {
  const r = render(<Settings token="tok" {...props} />)
  await screen.findByRole('button', { name: 'Save Settings' })
  return r
}

describe('Settings — carga', () => {
  it('pinta General por defecto con los valores reales del servidor', async () => {
    servidor()
    await montar()
    expect(screen.getByLabelText('DNS Server Domain')).toHaveValue('ref.technitium-ui.test')
    expect(screen.getByLabelText('Default Record TTL')).toHaveValue('3600')
    expect(screen.getByText('seconds (default 3600/1h)')).toBeInTheDocument()
  })

  it('si el servidor falla, avisa en vez de reventar', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    render(<Settings token="tok" />)
    expect(await screen.findByText('Unable to load the DNS Server settings.')).toBeInTheDocument()
  })

  it('la sub-pestaña activa llega por prop: la sub-navegación es del Shell', async () => {
    servidor()
    await montar({ sub: 'Logging' })
    expect(screen.getByLabelText('Log Folder Path')).toBeInTheDocument()
    expect(screen.queryByLabelText('DNS Server Domain')).not.toBeInTheDocument()
  })

  it('las nueve sub-pestañas pintan sin romperse', async () => {
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
    for (const [sub, marca] of subs) {
      const { unmount } = render(<Settings token="tok" sub={sub} />)
      expect(await screen.findByText(marca)).toBeInTheDocument()
      unmount()
    }
  })
})

describe('Settings — guardar', () => {
  it('manda settings/set por POST con los campos de las nueve sub-pestañas', async () => {
    const spy = servidor()
    await montar({ sub: 'Logging' })
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    const llamada = await waitFor(() => {
      const c = spy.mock.calls.find((c) => c[0] === 'settings/set')
      expect(c).toBeDefined()
      return c!
    })
    expect(llamada[1]?.method).toBe('POST')
    const body = llamada[1]!.body as Record<string, string>
    expect(body.dnsServerDomain).toBe('ref.technitium-ui.test')
    expect(body.loggingType).toBe('File')
    expect(body.recursion).toBe('AllowOnlyForPrivateNetworks')
  })

  it('al guardar bien, el aviso es el literal de upstream', async () => {
    servidor()
    await montar()
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Settings Saved!')).toBeInTheDocument()
    expect(screen.getByText('DNS Server settings were saved successfully.')).toBeInTheDocument()
  })

  it('un error del servidor sale con su errorMessage bajo el título Error!', async () => {
    vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'settings/get') return ok({ response: AJUSTES })
      return { kind: 'error' as const, message: 'Invalid Web Service HTTPS port.' }
    })
    await montar()
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Error!')).toBeInTheDocument()
    expect(screen.getByText('Invalid Web Service HTTPS port.')).toBeInTheDocument()
  })

  it('un campo vacío bloquea el guardado con el aviso literal, y no llama al servidor', async () => {
    const spy = servidor()
    await montar()
    await userEvent.clear(screen.getByLabelText('DNS Server Domain'))
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    expect(await screen.findByText('Please enter server domain name.')).toBeInTheDocument()
    expect(screen.getByText('Missing!')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'settings/set')).toBeUndefined()
  })

  it('si el campo que falta está en otra sub-pestaña, la pantalla salta a ella', async () => {
    servidor()
    const onSubChange = vi.fn()
    await montar({ sub: 'Recursion', onSubChange })
    await userEvent.clear(screen.getByLabelText('Resolver Retries'))
    // Se cambia a otra sub-pestaña antes de guardar para probar el salto.
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))

    expect(await screen.findByText('Please enter a value for Resolver Retries.')).toBeInTheDocument()
    expect(onSubChange).toHaveBeenCalledWith('Recursion')
  })

  it('el salto por validación se deshace en cuanto el Shell pide otra sub-pestaña', async () => {
    servidor()
    const { rerender } = await montar({ sub: 'General' })
    await userEvent.clear(screen.getByLabelText('DNS Server Domain'))
    await userEvent.click(screen.getByRole('button', { name: 'Save Settings' }))
    expect(await screen.findByText('Please enter server domain name.')).toBeInTheDocument()

    rerender(<Settings token="tok" sub="Logging" />)
    expect(await screen.findByLabelText('Log Folder Path')).toBeInTheDocument()
    expect(screen.queryByLabelText('DNS Server Domain')).not.toBeInTheDocument()
  })
})

describe('Settings — Blocking', () => {
  it('sin fecha, las etiquetas son «Not Set» y «Not Scheduled»', async () => {
    servidor()
    await montar({ sub: 'Blocking' })
    expect(screen.getByText('Not Set')).toBeInTheDocument()
    expect(screen.getByText('Not Scheduled')).toBeInTheDocument()
  })

  it('«Update Now» está apagado si no hay listas configuradas', async () => {
    servidor()
    await montar({ sub: 'Blocking' })
    expect(screen.getByRole('button', { name: 'Update Now' })).toBeDisabled()
  })

  it('apagar «Enable Blocking» apaga el resto de la sub-pestaña', async () => {
    servidor()
    await montar({ sub: 'Blocking' })
    expect(screen.getByLabelText('Allow TXT Blocking Report')).toBeEnabled()
    await userEvent.click(screen.getByLabelText('Enable Blocking'))
    expect(screen.getByLabelText('Allow TXT Blocking Report')).toBeDisabled()
    expect(screen.getByLabelText('Blocking Bypass List')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Temporary Disable Now' })).toBeDisabled()
  })

  it('sin minutos, «Temporary Disable Now» avisa con el texto literal', async () => {
    servidor()
    await montar({ sub: 'Blocking' })
    await userEvent.click(screen.getByRole('button', { name: 'Temporary Disable Now' }))
    expect(
      await screen.findByText('Please enter a value in minutes to temporarily disable blocking.'),
    ).toBeInTheDocument()
  })

  it('con minutos, confirma y llama al endpoint con el aviso de éxito literal', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'settings/get') return ok({ response: AJUSTES })
      if (path === 'settings/temporaryDisableBlocking') {
        return ok({ response: { temporaryDisableBlockingTill: '2026-08-25T14:00:00Z' } })
      }
      return ok({ response: {} })
    })
    await montar({ sub: 'Blocking' })

    await userEvent.type(screen.getByLabelText('Blocking Temporarily Disabled Till'), '15')
    await userEvent.click(screen.getByRole('button', { name: 'Temporary Disable Now' }))
    expect(
      await screen.findByText('Are you sure to temporarily disable blocking for 15 minute(s)?'),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'OK' }))

    const llamada = await waitFor(() => {
      const c = spy.mock.calls.find((c) => c[0] === 'settings/temporaryDisableBlocking')
      expect(c).toBeDefined()
      return c!
    })
    expect(llamada[1]?.body).toEqual({ minutes: '15' })
    expect(await screen.findByText('Blocking Disabled!')).toBeInTheDocument()
    expect(
      screen.getByText('Blocking was successfully disabled temporarily for 15 minute(s).'),
    ).toBeInTheDocument()
    // main.js:2393 — el éxito además desmarca «Enable Blocking».
    expect(screen.getByLabelText('Enable Blocking')).not.toBeChecked()
  })

  it('«Update Now» confirma y dispara forceUpdateBlockLists', async () => {
    const spy = servidor({ blockListUrls: ['https://example.com/list.txt'] })
    await montar({ sub: 'Blocking' })

    await userEvent.click(screen.getByRole('button', { name: 'Update Now' }))
    expect(
      await screen.findByText('Are you sure to force download and update the block lists?'),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'OK' }))

    await waitFor(() =>
      expect(spy.mock.calls.find((c) => c[0] === 'settings/forceUpdateBlockLists')).toBeDefined(),
    )
    expect(await screen.findByText('Updating Block List!')).toBeInTheDocument()
    expect(screen.getByText('Block list update was triggered successfully.')).toBeInTheDocument()
    expect(screen.getByText('Updating Now')).toBeInTheDocument()
  })
})

describe('Settings — barra de acciones', () => {
  it('«Flush Cache» confirma y llama a cache/flush con su aviso literal', async () => {
    const spy = servidor()
    await montar()
    await userEvent.click(screen.getByRole('button', { name: 'Flush Cache' }))
    expect(await screen.findByText('Are you sure to flush the DNS Server cache?')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'OK' }))

    await waitFor(() => expect(spy.mock.calls.find((c) => c[0] === 'cache/flush')).toBeDefined())
    expect(await screen.findByText('Flushed!')).toBeInTheDocument()
    expect(screen.getByText('DNS Server cache was flushed successfully.')).toBeInTheDocument()
  })

  it('los permisos gobiernan cada botón por separado', async () => {
    servidor()
    render(<Settings token="tok" canModify={false} canFlushCache={false} canBackup />)
    await screen.findByRole('button', { name: 'Backup Settings' })
    expect(screen.queryByRole('button', { name: 'Save Settings' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Flush Cache' })).not.toBeInTheDocument()
  })

  it('el backup sin nada marcado avisa con el texto literal', async () => {
    servidor()
    await montar()
    await userEvent.click(screen.getByRole('button', { name: 'Backup Settings' }))
    for (const etiqueta of [
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
      await userEvent.click(screen.getByLabelText(etiqueta))
    }
    await userEvent.click(screen.getByRole('button', { name: 'Backup' }))
    expect(await screen.findByText('Please select at least one item to backup.')).toBeInTheDocument()
  })

  it('la restauración sin fichero avisa antes de mirar los elementos', async () => {
    servidor()
    await montar()
    await userEvent.click(screen.getByRole('button', { name: 'Restore Settings' }))
    await userEvent.click(screen.getByRole('button', { name: 'Restore' }))
    expect(await screen.findByText('Please select a backup zip file to restore.')).toBeInTheDocument()
  })
})

describe('Settings — reglas de habilitado del resto de sub-pestañas', () => {
  it('la ACL de recursión sólo se puede editar con la cuarta opción', async () => {
    servidor()
    await montar({ sub: 'Recursion' })
    const acl = screen.getByLabelText('Network Access Control List (ACL)')
    expect(acl).toBeDisabled()
    await userEvent.click(screen.getByLabelText('Use Specified Network Access Control List (ACL)'))
    expect(acl).toBeEnabled()
  })

  it('los campos del proxy se despiertan al elegir un tipo', async () => {
    servidor()
    await montar({ sub: 'Proxy & Forwarders' })
    expect(screen.getByLabelText('Proxy Server Address')).toBeDisabled()
    await userEvent.click(screen.getByLabelText('SOCKS5 Proxy'))
    expect(screen.getByLabelText('Proxy Server Address')).toBeEnabled()
  })

  it('«None» en el registro apaga sus cuatro opciones y la carpeta', async () => {
    servidor()
    await montar({ sub: 'Logging' })
    expect(screen.getByLabelText('Log All Queries')).toBeEnabled()
    await userEvent.click(screen.getByLabelText('None'))
    expect(screen.getByLabelText('Log All Queries')).toBeDisabled()
    expect(screen.getByLabelText('Log Folder Path')).toBeDisabled()
  })

  it('la tabla TSIG añade y borra filas', async () => {
    servidor()
    await montar({ sub: 'TSIG' })
    expect(screen.queryByLabelText('Key Name 1')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByLabelText('Key Name 1')).toBeInTheDocument()
    // El algoritmo por defecto de una fila nueva es hmac-sha256.
    expect(valorDe(screen.getByLabelText('Algorithm 1'))).toBe('HMAC-SHA256 (recommended)')
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(screen.queryByLabelText('Key Name 1')).not.toBeInTheDocument()
  })

  it('la tabla QPM llega con las filas reales del servidor', async () => {
    servidor()
    await montar()
    expect(screen.getByLabelText('IPv4 Prefix 1')).toHaveValue(32)
    expect(screen.getByLabelText('IPv4 UDP Limit 2')).toHaveValue(6000)
    expect(screen.getByLabelText('IPv6 Prefix 3')).toHaveValue(56)
  })
})
