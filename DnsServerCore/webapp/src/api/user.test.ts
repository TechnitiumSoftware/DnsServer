import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { checkForUpdate, deleteSession, openDownload, DISABLE_UPDATE_NOTIFICATION_KEY } from './user'
import * as client from './client'

beforeEach(() => localStorage.clear())
afterEach(() => vi.restoreAllMocks())

describe('deleteSession', () => {
  it('it sends the partialToken', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await deleteSession('t', 'abc123')
    expect(spy.mock.calls[0][0]).toBe('user/session/delete')
    expect(spy.mock.calls[0][1]?.body).toEqual({ partialToken: 'abc123' })
  })
})

describe('checkForUpdate', () => {
  it('it does not call the server if the notice is silenced', async () => {
    localStorage.setItem(DISABLE_UPDATE_NOTIFICATION_KEY, 'true')
    const spy = vi.spyOn(client, 'apiRequest')
    expect(await checkForUpdate('t')).toEqual({ kind: 'skipped' })
    expect(spy).not.toHaveBeenCalled()
  })

  it('an explicit force skips the silence', async () => {
    localStorage.setItem(DISABLE_UPDATE_NOTIFICATION_KEY, 'true')
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await checkForUpdate('t', true)
    expect(spy).toHaveBeenCalledOnce()
  })

  it('it calls the server when it is not silenced', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await checkForUpdate('t')
    expect(spy.mock.calls[0][0]).toBe('user/checkForUpdate')
  })
})

describe('openDownload', () => {
  it('it asks for a single-use token and puts it in the query', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', response: { token: 'unico' } },
    })
    const open = vi.fn()
    vi.stubGlobal('open', open)
    const r = await openDownload('t', 'settings/backup', { zones: 'true' })
    expect(r.ok).toBe(true)
    expect(r.url).toContain('api/settings/backup?')
    expect(r.url).toContain('token=unico')
    expect(r.url).toContain('zones=true')
    expect(open).toHaveBeenCalledWith(r.url, '_blank')
    vi.unstubAllGlobals()
  })

  it('it opens nothing if it cannot get the token', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    const open = vi.fn()
    vi.stubGlobal('open', open)
    expect((await openDownload('t', 'settings/backup')).ok).toBe(false)
    expect(open).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })
})
