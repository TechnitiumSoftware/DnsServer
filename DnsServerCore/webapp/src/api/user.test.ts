import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { checkForUpdate, deleteSession, openDownload, DISABLE_UPDATE_NOTIFICATION_KEY } from './user'
import * as client from './client'

beforeEach(() => localStorage.clear())
afterEach(() => vi.restoreAllMocks())

describe('deleteSession', () => {
  it('manda el partialToken', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await deleteSession('t', 'abc123')
    expect(spy.mock.calls[0][0]).toBe('user/session/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ partialToken: 'abc123' })
  })
})

describe('checkForUpdate', () => {
  it('no llama al servidor si el aviso está silenciado', async () => {
    localStorage.setItem(DISABLE_UPDATE_NOTIFICATION_KEY, 'true')
    const spy = vi.spyOn(client, 'apiRequest')
    expect(await checkForUpdate('t')).toEqual({ kind: 'skipped' })
    expect(spy).not.toHaveBeenCalled()
  })

  it('un force explícito se salta el silencio', async () => {
    localStorage.setItem(DISABLE_UPDATE_NOTIFICATION_KEY, 'true')
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await checkForUpdate('t', true)
    expect(spy).toHaveBeenCalledOnce()
  })

  it('llama al servidor cuando no está silenciado', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await checkForUpdate('t')
    expect(spy.mock.calls[0][0]).toBe('user/checkForUpdate')
  })
})

describe('openDownload', () => {
  it('pide un token de un solo uso y lo pone en la query', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { token: 'unico' } },
    })
    const abrir = vi.fn()
    vi.stubGlobal('open', abrir)
    const r = await openDownload('t', 'settings/backup', { zones: 'true' })
    expect(r.ok).toBe(true)
    expect(r.url).toContain('api/settings/backup?')
    expect(r.url).toContain('token=unico')
    expect(r.url).toContain('zones=true')
    expect(abrir).toHaveBeenCalledWith(r.url, '_blank')
    vi.unstubAllGlobals()
  })

  it('no abre nada si no consigue el token', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    const abrir = vi.fn()
    vi.stubGlobal('open', abrir)
    expect((await openDownload('t', 'settings/backup')).ok).toBe(false)
    expect(abrir).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })
})
