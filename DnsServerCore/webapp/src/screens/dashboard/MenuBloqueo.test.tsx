import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MenuBloqueo } from './MenuBloqueo'
import * as api from '../../api/settings'

afterEach(() => vi.restoreAllMocks())

/*
El menú «Blocking» de la cabecera de «Top Blocked Domains». Upstream lo tiene y
aquí faltaba entero: apagar el bloqueo un rato es de lo que más se hace en esta
consola y obligaba a irse a Settings a buscarlo.
*/
const abrir = async () =>
  await userEvent.click(await screen.findByRole('button', { name: 'Blocking options' }))

describe('MenuBloqueo', () => {
  it('pregunta el estado AL ABRIR, no al pintar', async () => {
    const spy = vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<MenuBloqueo token="t" onAviso={() => {}} />)
    // Entre pintar y abrir, el ajuste puede haber cambiado en otra pestaña.
    expect(spy).not.toHaveBeenCalled()
    await abrir()
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('con el bloqueo encendido ofrece apagarlo, y nunca las dos cosas', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<MenuBloqueo token="t" onAviso={() => {}} />)
    await abrir()
    expect(await screen.findByRole('menuitem', { name: 'Disable Blocking' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Enable Blocking' })).not.toBeInTheDocument()
  })

  it('con el bloqueo apagado ofrece encenderlo', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: false } as never)
    render(<MenuBloqueo token="t" onAviso={() => {}} />)
    await abrir()
    expect(await screen.findByRole('menuitem', { name: 'Enable Blocking' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Disable Blocking' })).not.toBeInTheDocument()
  })

  it('ofrece los ocho plazos de upstream, con sus rótulos', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<MenuBloqueo token="t" onAviso={() => {}} />)
    await abrir()
    for (const r of [
      'Disable Blocking For 1 Minute',
      'Disable Blocking For 2 Minutes',
      'Disable Blocking For 5 Minutes',
      'Disable Blocking For 10 Minutes',
      'Disable Blocking For 15 Minutes',
      'Disable Blocking For 30 Minutes',
      'Disable Blocking For 1 Hour',
      'Disable Blocking For 3 Hours',
    ]) {
      expect(await screen.findByRole('menuitem', { name: r })).toBeInTheDocument()
    }
  })

  it('apagar un rato confirma primero y manda los minutos', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    const spy = vi.spyOn(api, 'temporaryDisableBlocking').mockResolvedValue('2026-08-31T08:00:00Z')
    const avisos: { title: string; text: string }[] = []
    render(<MenuBloqueo token="t" onAviso={(a) => avisos.push(a)} />)
    await abrir()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable Blocking For 15 Minutes' }))

    // Nada ha pasado todavía: primero se pregunta, con el texto de upstream.
    expect(spy).not.toHaveBeenCalled()
    expect(
      await screen.findByText('Are you sure to temporarily disable blocking for 15 minute(s)?'),
    ).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Disable' }))
    expect(spy).toHaveBeenCalledWith('t', '15')
    expect(avisos).toEqual([
      {
        type: 'success',
        title: 'Blocking Disabled!',
        text: 'Blocking was successfully disabled temporarily for 15 minute(s).',
      },
    ])
  })

  it('cancelar no toca nada', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    const spy = vi.spyOn(api, 'temporaryDisableBlocking').mockResolvedValue('x')
    render(<MenuBloqueo token="t" onAviso={() => {}} />)
    await abrir()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable Blocking For 1 Hour' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(spy).not.toHaveBeenCalled()
  })

  it('encender manda enableBlocking=true y avisa con el texto de upstream', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: false } as never)
    const spy = vi
      .spyOn(api, 'setSettings')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: {} } } as never)
    const avisos: { title: string; text: string }[] = []
    render(<MenuBloqueo token="t" onAviso={(a) => avisos.push(a)} />)
    await abrir()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Enable Blocking' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Enable' }))
    expect(spy).toHaveBeenCalledWith('t', { enableBlocking: 'true' })
    expect(avisos[0]).toEqual({
      type: 'success',
      title: 'Blocking Enabled!',
      text: 'Blocking was enabled successfully.',
    })
  })
})
