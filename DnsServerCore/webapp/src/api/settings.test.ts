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
  it('settings/get pide el nodo vacío y devuelve el contenido de `response`', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { dnsServerDomain: 'dns.test' } }))

    const s = await getSettings('tok')

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/get')!
    expect(llamada[1]).toMatchObject({ token: 'tok', body: { node: '' } })
    expect(s?.dnsServerDomain).toBe('dns.test')
  })

  it('settings/get devuelve null si el servidor falla, en vez de reventar', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getSettings('tok')).toBeNull()
  })

  it('settings/set va por POST con el cuerpo tal cual', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({ response: {} }))

    await setSettings('tok', { node: '', dnsServerDomain: 'dns.test' })

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/set')!
    expect(llamada[1]).toMatchObject({
      method: 'POST',
      token: 'tok',
      body: { node: '', dnsServerDomain: 'dns.test' },
    })
  })

  it('settings/set propaga el errorMessage del servidor', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'Invalid port.' })
    const outcome = await setSettings('tok', {})
    expect(outcome).toEqual({ kind: 'error', message: 'Invalid port.' })
  })

  it('settings/forceUpdateBlockLists se llama sin parámetros', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    expect(await forceUpdateBlockLists('tok')).toBe(true)
    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/forceUpdateBlockLists')!
    expect(llamada[1]).toEqual({ token: 'tok' })
  })

  it('settings/temporaryDisableBlocking manda los minutos y devuelve hasta cuándo', async () => {
    const spy = vi
      .spyOn(client, 'apiRequest')
      .mockResolvedValue(ok({ response: { temporaryDisableBlockingTill: '2026-08-25T14:00:00Z' } }))

    const till = await temporaryDisableBlocking('tok', '15')

    const llamada = spy.mock.calls.find((c) => c[0] === 'settings/temporaryDisableBlocking')!
    expect(llamada[1]).toMatchObject({ body: { minutes: '15' } })
    expect(till).toBe('2026-08-25T14:00:00Z')
  })

  it('cache/flush manda el nodo vacío', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(ok({}))
    expect(await flushCache('tok')).toBe(true)
    const llamada = spy.mock.calls.find((c) => c[0] === 'cache/flush')!
    expect(llamada[1]).toMatchObject({ body: { node: '' } })
  })

  it('la selección inicial del backup marca todo menos los logs', () => {
    const s = seleccionInicialBackup()
    expect(Object.keys(s)).toEqual(ELEMENTOS_BACKUP.map((e) => e.key))
    expect(s.logs).toBe(false)
    expect(s.authConfig).toBe(true)
  })

  it('los parámetros de backup mandan los trece elementos como true/false', () => {
    const p = parametrosBackup({ ...seleccionInicialBackup(), zones: false })
    expect(p.zones).toBe('false')
    expect(p.stats).toBe('true')
    expect(p.node).toBe('')
    expect(Object.keys(p)).toHaveLength(ELEMENTOS_BACKUP.length + 1)
  })

  it('settings/restore manda el fichero por multipart y las opciones en la query', async () => {
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
    // El cuerpo NO lleva las opciones: upstream las manda sólo por la query.
    expect(llamada[1]?.body).toBeUndefined()
  })

  it('settings/restore propaga invalid-token tal cual', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    const outcome = await restoreSettings('tok', new File([''], 'b.zip'), {}, false)
    expect(outcome.kind).toBe('invalid-token')
  })
})

// El tipo tiene que aceptar la respuesta real sin las claves nulas ausentes.
const _forma: Partial<DnsSettings> = { temporaryDisableBlockingTill: undefined }
void _forma

describe('getTsigKeyNames', () => {
  it('lo consume Zones, no Settings: devuelve la lista de nombres', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({
      kind: 'ok', data: { status: 'ok', response: { tsigKeyNames: ['transfer-key'] } },
    } as never)
    expect(await getTsigKeyNames('t')).toEqual(['transfer-key'])
  })

  it('devuelve lista vacía si falla, sin romper el modal de opciones de zona', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await getTsigKeyNames('t')).toEqual([])
  })
})
