import { describe, expect, it, vi, afterEach } from 'vitest'
import { listZones, getRecords, importZone, nuncaUsado, TIPOS_ZONA } from './zones'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())
const env = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

describe('zones', () => {
  it('ofrece los siete tipos de zona de upstream', () => {
    expect(TIPOS_ZONA).toEqual(['Primary','Secondary','Stub','Forwarder','SecondaryForwarder','Catalog','SecondaryCatalog'])
  })

  it('listZones pagina en el SERVIDOR: manda pageNumber y zonesPerPage', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(
      env({ zones: [], pageNumber: 2, totalPages: 5, totalZones: 47 }),
    )
    const r = await listZones('t', { pageNumber: 2, zonesPerPage: 10, filterName: 'ca' })
    expect(spy.mock.calls[0][0]).toBe('zones/list')
    expect(spy.mock.calls[0][1]?.body).toEqual({ filterName: 'ca', filterType: '', pageNumber: '2', zonesPerPage: '10' })
    expect(r).toEqual({ zones: [], pageNumber: 2, totalPages: 5, totalZones: 47 })
  })

  it('si el servidor omite la paginación, se rellena sin romper', async () => {
    // Comprobado en v15.4: sin pageNumber la respuesta trae sólo `zones`.
    vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ zones: [{ name: 'a' }, { name: 'b' }] }))
    const r = await listZones('t')
    expect(r).toMatchObject({ pageNumber: 1, totalPages: 1, totalZones: 2 })
  })

  it('getRecords NO pagina: pide listZone=true y sin parámetros de página', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ zone: { name: 'casa.test' }, records: [] }))
    await getRecords('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('zones/records/get')
    expect(spy.mock.calls[0][1]?.body).toEqual({ domain: 'casa.test', zone: 'casa.test', listZone: 'true' })
    expect(spy.mock.calls[0][1]?.body).not.toHaveProperty('pageNumber')
  })

  it('devuelve null si la llamada falla, en vez de reventar la pantalla', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await listZones('t')).toBeNull()
    expect(await getRecords('t', 'x')).toBeNull()
  })

  it('reconoce la fecha mínima de .NET como «nunca usado»', () => {
    expect(nuncaUsado('0001-01-01T00:00:00')).toBe(true)
    expect(nuncaUsado('2026-08-25T13:10:29Z')).toBe(false)
    expect(nuncaUsado('')).toBe(true)
  })

  it('importar una zona va como multipart, con el campo fileZone', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    const archivo = new File(['$ORIGIN casa.test.'], 'casa.zone')
    await importZone('t', 'casa.test', archivo, { overwrite: true })
    expect(spy.mock.calls[0][1]?.file?.campo).toBe('fileZone')
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ zone: 'casa.test', overwrite: 'true' })
  })
})
