import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  listZones,
  importZone,
  exportZone,
  nuncaUsado,
  serializarPermisos,
  getZoneOptions,
  getZonePermissions,
  setZonePermissions,
  listCatalogs,
  convertZone,
  TIPOS_ZONA,
} from './zones'
import * as client from './client'
import * as user from './user'

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
    expect(spy.mock.calls[0][1]?.body).toEqual({
      filterName: 'ca',
      filterType: '',
      pageNumber: '2',
      zonesPerPage: '10',
      node: '',
    })
    expect(r).toEqual({ kind: 'ok', data: { zones: [], pageNumber: 2, totalPages: 5, totalZones: 47 } })
  })

  it('si el servidor omite la paginación, se rellena sin romper', async () => {
    // Comprobado en v15.4: sin pageNumber la respuesta trae sólo `zones`.
    vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ zones: [{ name: 'a' }, { name: 'b' }] }))
    const r = await listZones('t')
    expect(r).toMatchObject({ kind: 'ok', data: { pageNumber: 1, totalPages: 1, totalZones: 2 } })
  })

  /*
  `listZones` sube el fallo entero y los demás siguen devolviendo `null`.

  La diferencia no es capricho: la lista de zonas es lo primero que se pinta al
  entrar en la pantalla, así que su fallo es el que el usuario ve y hay que
  contárselo con el motivo —antes se decía «Unable to reach the DNS server.»
  incluso cuando el servidor había contestado—. Los otros tres alimentan
  diálogos que ya avisan por su cuenta.
  */
  it('listZones sube el fallo con su motivo; los demás devuelven null', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await listZones('t')).toEqual({ kind: 'invalid-token' })
    expect(await getZoneOptions('t', 'x')).toBeNull()
    expect(await getZonePermissions('t', 'x')).toBeNull()
    expect(await listCatalogs('t')).toBeNull()
  })

  it('reconoce la fecha mínima de .NET como «nunca usado»', () => {
    expect(nuncaUsado('0001-01-01T00:00:00')).toBe(true)
    expect(nuncaUsado('2026-08-25T13:10:29Z')).toBe(false)
    expect(nuncaUsado('')).toBe(true)
  })

  it('importar por fichero va como multipart, con el campo fileImportZone', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    const archivo = new File(['$ORIGIN casa.test.'], 'casa.zone')
    await importZone('t', 'casa.test', { archivo }, {
      overwrite: true,
      overwriteZone: false,
      overwriteSoaSerial: false,
    })
    // Los interruptores viajan en la QUERY, no en el cuerpo (zone.js:1287).
    expect(spy.mock.calls[0][0]).toContain('zones/import?')
    expect(spy.mock.calls[0][0]).toContain('overwrite=true')
    expect(spy.mock.calls[0][0]).toContain('overwriteZone=false')
    expect(spy.mock.calls[0][1]?.file?.campo).toBe('fileImportZone')
  })

  it('importar pegando el texto va como text/plain, no como multipart', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await importZone('t', 'casa.test', { texto: '@ 3600 IN A 10.0.0.1' }, {
      overwrite: false,
      overwriteZone: true,
      overwriteSoaSerial: false,
    })
    expect(spy.mock.calls[0][1]?.texto).toBe('@ 3600 IN A 10.0.0.1')
    expect(spy.mock.calls[0][1]?.file).toBeUndefined()
  })

  it('exportar una zona pasa por el token de un solo uso y SIN `ts`', async () => {
    // zone.js:1322 no añade el rompe-cachés que sí llevan las descargas de
    // logs y la copia de ajustes. La URL tiene que salir igual.
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })
    await exportZone('t', 'casa.test')
    expect(spy).toHaveBeenCalledWith('t', 'zones/export', { zone: 'casa.test', node: '' })
  })

  it('options/get pide los catálogos disponibles en la misma llamada', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ name: 'casa.test' }))
    await getZoneOptions('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('zones/options/get')
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ includeAvailableCatalogZoneNames: 'true' })
  })

  it('permissions/get pide usuarios y grupos, y tolera listas ausentes', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ section: 'Zones' }))
    const r = await getZonePermissions('t', 'casa.test')
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ includeUsersAndGroups: 'true' })
    expect(r).toMatchObject({ userPermissions: [], groupPermissions: [] })
  })

  it('los permisos se serializan como nombre|ver|modificar|borrar por fila', () => {
    expect(
      serializarPermisos([
        { nombre: 'admin', canView: true, canModify: true, canDelete: false },
        { nombre: 'ana', canView: true, canModify: false, canDelete: false },
      ]),
    ).toBe('admin|true|true|false|ana|true|false|false')
  })

  it('una tabla de permisos vacía se serializa como cadena vacía', () => {
    expect(serializarPermisos([])).toBe('')
  })

  it('permissions/set manda las dos tablas ya serializadas', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await setZonePermissions('t', 'casa.test', 'a|true|true|true', '')
    expect(spy.mock.calls[0][0]).toBe('zones/permissions/set')
    expect(spy.mock.calls[0][1]?.body).toEqual({
      zone: 'casa.test',
      userPermissions: 'a|true|true|true',
      groupPermissions: '',
      node: '',
    })
  })

  it('todas las llamadas llevan `node`, aunque vaya vacío', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await convertZone('t', 'casa.test', 'Secondary')
    expect(spy.mock.calls[0][1]?.body).toHaveProperty('node', '')
  })
})
