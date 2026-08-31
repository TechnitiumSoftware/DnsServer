import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BlockingMenu } from './MenuBloqueo'
import * as api from '../../api/settings'

afterEach(() => vi.restoreAllMocks())

/*
The "Blocking" menu in the header of "Top Blocked Domains". Upstream has it and
here it was missing entirely: turning blocking off for a while is one of the most
frequent things done in this console and it forced a trip to Settings to find
it.
*/
const open = async () =>
  await userEvent.click(await screen.findByRole('button', { name: 'Blocking options' }))

describe('BlockingMenu', () => {
  it('it asks for the state ON OPENING, not when drawing', async () => {
    const spy = vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<BlockingMenu token="t" onAviso={() => {}} />)
    // Between drawing and opening, the setting may have changed in another tab.
    expect(spy).not.toHaveBeenCalled()
    await open()
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('with blocking on it offers to switch it off, and never both', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<BlockingMenu token="t" onAviso={() => {}} />)
    await open()
    expect(await screen.findByRole('menuitem', { name: 'Disable Blocking' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Enable Blocking' })).not.toBeInTheDocument()
  })

  it('with blocking off it offers to switch it on', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: false } as never)
    render(<BlockingMenu token="t" onAviso={() => {}} />)
    await open()
    expect(await screen.findByRole('menuitem', { name: 'Enable Blocking' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Disable Blocking' })).not.toBeInTheDocument()
  })

  it('it offers the eight upstream durations, with their labels', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    render(<BlockingMenu token="t" onAviso={() => {}} />)
    await open()
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

  it('switching off for a while confirms first and sends the minutes', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    const spy = vi.spyOn(api, 'temporaryDisableBlocking').mockResolvedValue('2026-08-31T08:00:00Z')
    const notices: { title: string; text: string }[] = []
    render(<BlockingMenu token="t" onAviso={(a) => notices.push(a)} />)
    await open()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable Blocking For 15 Minutes' }))

    // Nothing has happened yet: it asks first, with upstream's text.
    expect(spy).not.toHaveBeenCalled()
    expect(
      await screen.findByText('Are you sure to temporarily disable blocking for 15 minute(s)?'),
    ).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Disable' }))
    expect(spy).toHaveBeenCalledWith('t', '15')
    expect(notices).toEqual([
      {
        type: 'success',
        title: 'Blocking Disabled!',
        text: 'Blocking was successfully disabled temporarily for 15 minute(s).',
      },
    ])
  })

  it('cancelling touches nothing', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: true } as never)
    const spy = vi.spyOn(api, 'temporaryDisableBlocking').mockResolvedValue('x')
    render(<BlockingMenu token="t" onAviso={() => {}} />)
    await open()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable Blocking For 1 Hour' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(spy).not.toHaveBeenCalled()
  })

  it('switching on sends enableBlocking=true and alerts with the upstream text', async () => {
    vi.spyOn(api, 'getSettings').mockResolvedValue({ enableBlocking: false } as never)
    const spy = vi
      .spyOn(api, 'setSettings')
      .mockResolvedValue({ kind: 'ok', data: { status: 'ok', response: {} } } as never)
    const notices: { title: string; text: string }[] = []
    render(<BlockingMenu token="t" onAviso={(a) => notices.push(a)} />)
    await open()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Enable Blocking' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Enable' }))
    expect(spy).toHaveBeenCalledWith('t', { enableBlocking: 'true' })
    expect(notices[0]).toEqual({
      type: 'success',
      title: 'Blocking Enabled!',
      text: 'Blocking was enabled successfully.',
    })
  })
})
