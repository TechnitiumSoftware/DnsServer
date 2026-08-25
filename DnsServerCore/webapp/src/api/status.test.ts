import { describe, expect, it, vi, afterEach } from 'vitest'
import { getStatus } from './status'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())

describe('getStatus', () => {
  it('se pide sin token: es un endpoint público', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', hasDefaultCredentials: false, ssoEnabled: true },
    })
    await getStatus()
    expect(spy.mock.calls[0][0]).toBe('status')
    expect(spy.mock.calls[0][1]?.token).toBeUndefined()
  })

  it('lee la respuesta plana, sin envoltorio response', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok',
      data: { status: 'ok', hasDefaultCredentials: true, ssoEnabled: false },
    })
    const r = await getStatus()
    expect(r?.hasDefaultCredentials).toBe(true)
    expect(r?.ssoEnabled).toBe(false)
  })

  it('devuelve null si falla, sin reventar el login', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getStatus()).toBeNull()
  })
})
