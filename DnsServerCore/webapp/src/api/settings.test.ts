import { describe, expect, it, vi, afterEach } from 'vitest'
import * as client from './client'
import {
  ELEMENTOS_BACKUP,
  flushCache,
  forceUpdateBlockLists,
  getSettings,
  parametrosBackup,
  restoreSettings,
  seleccionInicialBackup,
  setSettings,
  temporaryDisableBlocking,
  type DnsSettings, getTsigKeyNames } from './settings'

afterEach(() => vi.restoreAllMocks())

function ok(data: unknown) {
  return { kind: 'ok' as const, data }
}

describe('api/settings', () => {
  it('settings/get asks with an empty node and returns the content of `response`', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { dnsServerDomain: 'dns.test' } }))

    const s = await getSettings('tok')

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/get')!
    expect(llamada[1]).toMatchObject({ token: 'tok', body: { node: '' } })
    expect(s?.dnsServerDomain).toBe('dns.test')
  })

  it('settings/get returns null if the server fails, instead of blowing up', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getSettings('tok')).toBeNull()
  })

  it('settings/set goes by POST with the body as it is', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: {} }))

    await setSettings('tok', { node: '', dnsServerDomain: 'dns.test' })

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/set')!
    expect(llamada[1]).toMatchObject({
      method: 'POST',
      token: 'tok',
      body: { node: '', dnsServerDomain: 'dns.test' },
    })
  })

  it('settings/set propagates the errorMessage from the server', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Invalid port.' })
    const outcome = await setSettings('tok', {})
    expect(outcome).toEqual({ kind: 'error', message: 'Invalid port.' })
  })

  it('settings/forceUpdateBlockLists is called with no parameters', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    expect(await forceUpdateBlockLists('tok')).toBe(true)
    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/forceUpdateBlockLists')!
    expect(llamada[1]).toEqual({ token: 'tok' })
  })

  it('settings/temporaryDisableBlocking sends the minutes and returns until when', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { temporaryDisableBlockingTill: '2026-08-25T14:00:00Z' } }))

    const till = await temporaryDisableBlocking('tok', '15')

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/temporaryDisableBlocking')!
    expect(llamada[1]).toMatchObject({ body: { minutes: '15' } })
    expect(till).toBe('2026-08-25T14:00:00Z')
  })

  it('cache/flush sends an empty node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    expect(await flushCache('tok')).toBe(true)
    const llamada = spy.mock.calls.find((c) => c[0] === 'cache/flush')!
    expect(llamada[1]).toMatchObject({ body: { node: '' } })
  })

  it('the initial backup selection checks everything except the logs', () => {
    const s = seleccionInicialBackup()
    expect(Object.keys(s)).toEqual(ELEMENTOS_BACKUP.map((e) => e.key))
    expect(s.logs).toBe(false)
    expect(s.authConfig).toBe(true)
  })

  it('the backup parameters send the thirteen items as true/false', () => {
    const p = parametrosBackup({ ...seleccionInicialBackup(), zones: false })
    expect(p.zones).toBe('false')
    expect(p.stats).toBe('true')
    expect(p.node).toBe('')
    expect(Object.keys(p)).toHaveLength(ELEMENTOS_BACKUP.length + 1)
  })

  it('settings/restore sends the file by multipart and the options in the query', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: {} }))

    const fichero = new File(['zip'], 'backup.zip')
    await restoreSettings('tok', fichero, seleccionInicialBackup(), true)

    const llamada = spy.mock.calls.find((c) => c[0].startsWith('settings/restore'))!
    expect(llamada[0]).toContain('deleteExistingFiles=true')
    expect(llamada[0]).toContain('logs=false')
    expect(llamada[0]).toContain('authConfig=true')
    expect(llamada[1]).toMatchObject({
      method: 'POST',
      token: 'tok',
      file: { campo: 'fileBackupZip', archivo: fichero },
    })
    // The body does NOT carry the options: upstream sends them by query only.
    expect(llamada[1]?.body).toBeUndefined()
  })

  it('settings/restore propaga invalid-token tal cual', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    const outcome = await restoreSettings('tok', new File([''], 'b.zip'), {}, false)
    expect(outcome.kind).toBe('invalid-token')
  })
})

// The type has to accept the real response without the absent null keys.
const _forma: Partial<DnsSettings> = { temporaryDisableBlockingTill: undefined }
void _forma

describe('getTsigKeyNames', () => {
  it('Zones consumes it, not Settings: it returns the list of names', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { tsigKeyNames: ['transfer-key'] } },
    } as never)
    expect(await getTsigKeyNames('t')).toEqual(['transfer-key'])
  })

  it('it returns an empty list on failure, without breaking the zone options modal', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await getTsigKeyNames('t')).toEqual([])
  })
})
