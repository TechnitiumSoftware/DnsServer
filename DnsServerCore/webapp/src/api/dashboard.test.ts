import { describe, expect, it, vi, afterEach } from 'vitest'
import { getDashboardStats, getTop, deleteAllStats, RANGOS, ETIQUETA_RANGO } from './dashboard'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())

const respuesta = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

describe('dashboard', () => {
  it('los seis rangos son los de upstream, con sus etiquetas literales', () => {
    expect(RANGOS).toEqual(['LastHour','LastDay','LastWeek','LastMonth','LastYear','Custom'])
    expect(ETIQUETA_RANGO.LastHour).toBe('Last Hour')
    expect(ETIQUETA_RANGO.LastMonth).toBe('Last Month')
  })

  it('pide el rango y desenvuelve response', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(respuesta({ stats: { totalQueries: 7 } }))
    const r = await getDashboardStats('t', 'LastDay')
    expect(spy.mock.calls[0][0]).toBe('dashboard/stats/get')
    expect(spy.mock.calls[0][1]?.body).toEqual({ type: 'LastDay' })
    expect(r.kind === 'ok' && r.data.stats.totalQueries).toBe(7)
  })

  it('sólo manda start y end cuando el rango es Custom', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(respuesta({}))
    await getDashboardStats('t', 'LastHour', { start: 'a', end: 'b' })
    expect(spy.mock.calls[0][1]?.body).toEqual({ type: 'LastHour' })
    spy.mockClear()
    await getDashboardStats('t', 'Custom', { start: 'a', end: 'b' })
    expect(spy.mock.calls[0][1]?.body).toEqual({ type: 'Custom', start: 'a', end: 'b' })
  })

  /*
  This test used to ask for `null` "so the screen does not blow up". Not blowing
  up was the problem: with `null` the Dashboard could not tell a failure apart
  from a server with no traffic, and drew eleven zeros.
  */
  it('sube el fallo del servidor, para que el Dashboard pueda decirlo', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'boom' })
    expect(await getDashboardStats('t')).toEqual({ kind: 'error', message: 'boom' })
  })

  it('getTop pide el tipo de lista y el límite', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(
      respuesta({ topClients: [{ name: '10.0.1.42', hits: 12 }] }),
    )
    const r = await getTop('t', 'LastHour', 'TopClients')
    expect(spy.mock.calls[0][1]?.body).toEqual({ type: 'LastHour', statsType: 'TopClients', limit: '1000' })
    expect(r[0].name).toBe('10.0.1.42')
  })

  it('getTop devuelve lista vacía si falla', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'x' })
    expect(await getTop('t', 'LastHour', 'TopDomains')).toEqual([])
  })

  it('deleteAllStats llama al endpoint correcto', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await deleteAllStats('t')
    expect(spy.mock.calls[0][0]).toBe('dashboard/stats/deleteAll')
  })
})
