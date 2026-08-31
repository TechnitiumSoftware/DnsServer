import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Apps } from './Apps'
import type { InstalledApp, StoreApp } from '../../api/apps'
import * as api from '../../api/apps'

afterEach(() => vi.restoreAllMocks())

const DETALLE = {
  classPath: 'NoData.App',
  description: 'Returns a NO DATA response.',
  recordDataTemplate: '{ "blockedTypes": [ "A" ] }',
  isAppRecordRequestHandler: true,
  isRequestController: false,
  isAuthoritativeRequestHandler: false,
  isRequestBlockingHandler: false,
  isQueryLogger: false,
  isQueryLogs: false,
  isPostProcessor: false,
}

const AL_DIA: InstalledApp = {
  name: 'What Is My Dns',
  description: 'Returns the IP address of the user DNS Server.',
  version: '9.0',
  updateVersion: '9.0',
  updateUrl: 'https://x/WhatIsMyDnsApp-v9.zip',
  updateAvailable: false,
  dnsApps: [DETALLE],
}

const CON_UPDATE: InstalledApp = {
  name: 'NO DATA',
  description: 'Allows creating APP records that return NO DATA.',
  version: '5.0',
  updateVersion: '6.0',
  updateUrl: 'https://x/NoDataApp-v6.zip',
  updateAvailable: true,
  dnsApps: [DETALLE],
}

function conApps(apps: InstalledApp[]) {
  return vi
    .spyOn(api, 'listApps')
    .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: { apps } } } as never)
}

function conTienda(storeApps: StoreApp[]) {
  return vi
    .spyOn(api, 'listStoreApps')
    .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: { storeApps } } } as never)
}

function tarjeta(nombre: string) {
  return within(screen.getByRole('listitem', { name: nombre }))
}

describe('Apps — lista de instaladas', () => {
  it('pinta una tarjeta por app, con nombre, versión y descripción', async () => {
    conApps([AL_DIA, CON_UPDATE])
    render(<Apps token="t" />)

    expect(await screen.findByRole('listitem', { name: 'What Is My Dns' })).toBeInTheDocument()
    expect(tarjeta('What Is My Dns').getByText(/v9\.0/)).toBeInTheDocument()
    expect(
      tarjeta('What Is My Dns').getByText('Returns the IP address of the user DNS Server.'),
    ).toBeInTheDocument()
  })

  it('anuncia en la cabecera cuántas apps tienen actualización', async () => {
    conApps([AL_DIA, CON_UPDATE])
    render(<Apps token="t" />)

    expect(await screen.findByText('1 update available')).toBeInTheDocument()
    // The installed count is gone: the header pill is for STATE, and counting
    // rows with that same look was an inconsistency.
    expect(screen.queryByText(/^\d+ instaladas?$/)).not.toBeInTheDocument()
  })

  it('sin actualizaciones no enseña la píldora', async () => {
    conApps([AL_DIA])
    render(<Apps token="t" />)

    await screen.findByRole('listitem', { name: 'What Is My Dns' })
    expect(screen.queryByText(/update available/)).not.toBeInTheDocument()
  })

  it('anuncia la versión nueva y ofrece «Store Update» sólo si la hay', async () => {
    conApps([AL_DIA, CON_UPDATE])
    render(<Apps token="t" />)

    await screen.findByRole('listitem', { name: 'NO DATA' })
    expect(tarjeta('NO DATA').getByText('Update v6.0')).toBeInTheDocument()
    expect(tarjeta('NO DATA').getByRole('button', { name: 'Store Update' })).toBeInTheDocument()
    expect(
      tarjeta('What Is My Dns').queryByRole('button', { name: 'Store Update' }),
    ).not.toBeInTheDocument()
  })

  /* apps.js:129-132 — "Update" (your own zip) and "Store Update" are two
     different actions, not two names for the same one. */
  it('cada tarjeta ofrece Config, Update y Uninstall', async () => {
    conApps([AL_DIA])
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    for (const n of ['Config', 'Update', 'Uninstall']) {
      expect(tarjeta('What Is My Dns').getByRole('button', { name: n })).toBeInTheDocument()
    }
  })

  it('el detalle enseña la clase, sus etiquetas y la plantilla de datos', async () => {
    conApps([AL_DIA])
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByText('More Details'))
    expect(tarjeta('What Is My Dns').getByText('NoData.App')).toBeInTheDocument()
    expect(tarjeta('What Is My Dns').getByText('APP Record')).toBeInTheDocument()
    expect(tarjeta('What Is My Dns').getByText(/blockedTypes/)).toBeInTheDocument()
  })

  it('sin apps instaladas explica qué son y ofrece abrir la tienda', async () => {
    conApps([])
    conTienda([])
    render(<Apps token="t" />)

    expect(await screen.findByText('No apps installed')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open App Store' })).toBeInTheDocument()
    expect(screen.queryByText('0 instaladas')).not.toBeInTheDocument()
  })

  it('si el servidor falla, lo dice y no revienta', async () => {
    vi.spyOn(api, 'listApps').mockResolvedValue({ kind: 'error', message: 'Boom' })
    render(<Apps token="t" />)

    expect(await screen.findByText('Boom')).toBeInTheDocument()
  })
})

describe('Apps — desinstalar', () => {
  /*
  The confirmation is the console's dialog, not the browser's native
  `confirm()`: uninstalling an app was one of the three steps that still opened
  the operating system's. The text is still upstream's literal (`apps.js:425`).
  */
  it('pide confirmación con el texto literal de upstream', async () => {
    conApps([AL_DIA])
    const spy = vi.spyOn(api, 'uninstallApp')
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Uninstall' }))
    expect(
      screen.getByText(
        "Are you sure you want to uninstall the DNS application 'What Is My Dns'?",
      ),
    ).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
  })

  it('al confirmar desinstala y avisa con el texto literal', async () => {
    conApps([AL_DIA])
    const spy = vi
      .spyOn(api, 'uninstallApp')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok' } } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Uninstall' }))
    await userEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Uninstall' }),
    )
    expect(spy.mock.calls[0][1]).toBe('What Is My Dns')
    expect(
      await screen.findByText("DNS application 'What Is My Dns' was uninstalled successfully."),
    ).toBeInTheDocument()
  })
})

describe('Apps — Store Update desde la tarjeta', () => {
  it('actualiza con el nombre y la url del app y avisa con el texto literal', async () => {
    conApps([CON_UPDATE])
    const spy = vi
      .spyOn(api, 'downloadAndUpdate')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok' } } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'NO DATA' })

    await userEvent.click(tarjeta('NO DATA').getByRole('button', { name: 'Store Update' }))
    expect(spy.mock.calls[0][1]).toBe('NO DATA')
    expect(spy.mock.calls[0][2]).toBe('https://x/NoDataApp-v6.zip')
    expect(
      await screen.findByText(
        "DNS application 'NO DATA' was updated successfully from DNS App Store.",
      ),
    ).toBeInTheDocument()
  })
})

describe('Apps — config de la app', () => {
  it('lee la config del nodo primario y la abre en un editor de texto', async () => {
    conApps([AL_DIA])
    const spy = vi.spyOn(api, 'getAppConfig').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { config: '{ "a": 1 }' } },
    } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Config' }))
    expect(spy.mock.calls[0][1]).toBe('What Is My Dns')
    expect(await screen.findByText('App Config - What Is My Dns')).toBeInTheDocument()
    expect(screen.getByLabelText('Config File')).toHaveValue('{ "a": 1 }')
  })

  /* The server returns `config: null` as soon as someone saves an empty one. */
  it('una config nula abre el editor vacío, no con «null»', async () => {
    conApps([AL_DIA])
    vi.spyOn(api, 'getAppConfig').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { config: null } },
    } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Config' }))
    expect(await screen.findByLabelText('Config File')).toHaveValue('')
  })

  it('guarda lo escrito y avisa con el texto literal', async () => {
    conApps([AL_DIA])
    vi.spyOn(api, 'getAppConfig').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { config: '' } },
    } as never)
    const spy = vi
      .spyOn(api, 'setAppConfig')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok' } } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Config' }))
    await userEvent.type(await screen.findByLabelText('Config File'), 'hola')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls[0][1]).toBe('What Is My Dns')
    expect(spy.mock.calls[0][2]).toBe('hola')
    expect(
      await screen.findByText(
        "The DNS application 'What Is My Dns' config was saved and reloaded successfully.",
      ),
    ).toBeInTheDocument()
  })
})

describe('Apps — instalar desde fichero', () => {
  it('exige el nombre ANTES que el fichero, con los textos literales', async () => {
    conApps([])
    conTienda([])
    render(<Apps token="t" />)
    await screen.findByText('No apps installed')

    await userEvent.click(screen.getByRole('button', { name: 'Install from file' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Install' }))
    expect(await screen.findByText('Please enter an application name.')).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('App Name'), 'Mía')
    await userEvent.click(screen.getByRole('button', { name: 'Install' }))
    expect(
      await screen.findByText('Please select an application zip file to install.'),
    ).toBeInTheDocument()
  })

  it('con nombre y fichero llama a installApp', async () => {
    conApps([])
    conTienda([])
    const spy = vi.spyOn(api, 'installApp')
    render(<Apps token="t" />)
    await screen.findByText('No apps installed')

    await userEvent.click(screen.getByRole('button', { name: 'Install from file' }))
    await userEvent.type(await screen.findByLabelText('App Name'), 'Mía')
    await userEvent.upload(screen.getByLabelText('App Zip File'), new File(['x'], 'a.zip'))
    await userEvent.click(screen.getByRole('button', { name: 'Install' }))

    expect(spy.mock.calls[0][1]).toBe('Mía')
    expect((spy.mock.calls[0][2] as File).name).toBe('a.zip')
  })
})

describe('Apps — actualizar desde fichero', () => {
  it('trae el nombre puesto y sin poder cambiarlo, y exige el fichero', async () => {
    conApps([AL_DIA])
    const spy = vi.spyOn(api, 'updateApp')
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'What Is My Dns' })

    await userEvent.click(tarjeta('What Is My Dns').getByRole('button', { name: 'Update' }))
    expect(await screen.findByLabelText('App Name')).toHaveValue('What Is My Dns')
    expect(screen.getByLabelText('App Name')).toBeDisabled()

    const modal = within(screen.getByRole('dialog'))
    await userEvent.click(modal.getByRole('button', { name: 'Update' }))
    expect(
      await screen.findByText('Please select an application zip file to update.'),
    ).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
  })
})

const TIENDA: StoreApp[] = [
  {
    name: 'Advanced Blocking',
    description: 'Blocks domain names using block lists.',
    version: '11.1',
    url: 'https://x/AdvancedBlockingApp-v11.1.zip',
    size: '61.54 KB',
    installed: false,
  },
  {
    name: 'NO DATA',
    description: 'Returns NO DATA.',
    version: '6.0',
    url: 'https://x/NoDataApp-v6.zip',
    size: '12.01 KB',
    installed: true,
    installedVersion: '5.0',
    updateAvailable: true,
  },
]

async function abrirTienda() {
  await userEvent.click(screen.getByRole('button', { name: 'App Store' }))
  return await screen.findByText('DNS App Store')
}

describe('Apps — tienda', () => {
  it('lista lo disponible con versión, zip y tamaño', async () => {
    conApps([CON_UPDATE])
    conTienda(TIENDA)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'NO DATA' })
    await abrirTienda()

    const fila = within(await screen.findByRole('listitem', { name: 'Advanced Blocking' }))
    expect(fila.getByText('Version 11.1')).toBeInTheDocument()
    expect(fila.getByText(/61\.54 KB/)).toBeInTheDocument()
    expect(fila.getByText(/AdvancedBlockingApp-v11\.1\.zip/)).toBeInTheDocument()
    expect(screen.getByText('Total Apps: 2')).toBeInTheDocument()
  })

  it('una instalada enseña su versión instalada, la nueva, Update y Uninstall', async () => {
    conApps([CON_UPDATE])
    conTienda(TIENDA)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'NO DATA' })
    await abrirTienda()

    const fila = within(
      await within(screen.getByRole('dialog')).findByRole('listitem', { name: 'NO DATA' }),
    )
    expect(fila.getByText('Version 5.0')).toBeInTheDocument()
    expect(fila.getByText('Update 6.0')).toBeInTheDocument()
    expect(fila.queryByRole('button', { name: 'Install' })).not.toBeInTheDocument()
    expect(fila.getByRole('button', { name: 'Update' })).toBeInTheDocument()
    expect(fila.getByRole('button', { name: 'Uninstall' })).toBeInTheDocument()
  })

  it('instalar llama a downloadAndInstall y avisa con el texto literal', async () => {
    conApps([])
    conTienda(TIENDA)
    const spy = vi
      .spyOn(api, 'downloadAndInstall')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok' } } as never)
    render(<Apps token="t" />)
    await screen.findByText('No apps installed')
    await abrirTienda()

    const fila = within(await screen.findByRole('listitem', { name: 'Advanced Blocking' }))
    await userEvent.click(fila.getByRole('button', { name: 'Install' }))
    expect(spy.mock.calls[0][1]).toBe('Advanced Blocking')
    expect(spy.mock.calls[0][2]).toBe('https://x/AdvancedBlockingApp-v11.1.zip')
    expect(
      await screen.findByText(
        "DNS application 'Advanced Blocking' was installed successfully from DNS App Store.",
      ),
    ).toBeInTheDocument()
  })

  it('desinstalar desde la tienda confirma con el literal y avisa con el suyo propio', async () => {
    conApps([CON_UPDATE])
    conTienda(TIENDA)
    vi.spyOn(api, 'uninstallApp').mockResolvedValue({ kind: 'ok', data: { status: 'ok' } } as never)
    render(<Apps token="t" />)
    await screen.findByRole('listitem', { name: 'NO DATA' })
    await abrirTienda()

    const fila = within(
      await within(screen.getAllByRole('dialog')[0]).findByRole('listitem', { name: 'NO DATA' }),
    )
    await userEvent.click(fila.getByRole('button', { name: 'Uninstall' }))
    // The confirmation stacks over the store's dialog.
    await userEvent.click(
      within(screen.getAllByRole('dialog').at(-1)!).getByRole('button', { name: 'Uninstall' }),
    )
    expect(
      await screen.findByText("DNS application 'NO DATA' was uninstalled successfully."),
    ).toBeInTheDocument()
  })

  it('una tienda vacía lo dice con el texto de upstream', async () => {
    conApps([])
    conTienda([])
    render(<Apps token="t" />)
    await screen.findByText('No apps installed')
    await abrirTienda()

    expect(await screen.findByText('No Apps Found')).toBeInTheDocument()
  })
})
