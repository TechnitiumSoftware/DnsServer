import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  listZones,
  importZone,
  exportZone,
  neverUsed,
  serializePermissions,
  getZoneOptions,
  getZonePermissions,
  setZonePermissions,
  listCatalogs,
  convertZone,
  ZONE_TYPES,
} from './zones'
import * as client from './client'
import * as user from './user'

afterEach(() => vi.restoreAllMocks())
const env = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

describe('zones', () => {
  it('offers the seven zone types of upstream', () => {
    expect(ZONE_TYPES).toEqual(['Primary','Secondary','Stub','Forwarder','SecondaryForwarder','Catalog','SecondaryCatalog'])
  })

  it('listZones paginates on the SERVER: it sends pageNumber and zonesPerPage', async () => {
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

  it('if the server omits the pagination, it is filled in without breaking', async () => {
    // Checked on v15.4: without pageNumber the response brings only `zones`.
    vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ zones: [{ name: 'a' }, { name: 'b' }] }))
    const r = await listZones('t')
    expect(r).toMatchObject({ kind: 'ok', data: { pageNumber: 1, totalPages: 1, totalZones: 2 } })
  })

  /*
  `listZones` raises the whole failure and the rest still return `null`.

  The difference is not a whim: the zone list is the first thing drawn on
  entering the screen, so its failure is the one the user sees and it has to be
  told with its reason —it used to say "Unable to reach the DNS server." even
  when the server had answered. The other three feed dialogs that already warn on
  their own.
  */
  it('listZones raises the failure with its reason; the rest return null', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'invalid-token' })
    expect(await listZones('t')).toEqual({ kind: 'invalid-token' })
    expect(await getZoneOptions('t', 'x')).toBeNull()
    expect(await getZonePermissions('t', 'x')).toBeNull()
    expect(await listCatalogs('t')).toBeNull()
  })

  it('recognises the .NET minimum date as "never used"', () => {
    expect(neverUsed('0001-01-01T00:00:00')).toBe(true)
    expect(neverUsed('2026-08-25T13:10:29Z')).toBe(false)
    expect(neverUsed('')).toBe(true)
  })

  it('importing by file goes as multipart, with the fileImportZone field', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    const archivo = new File(['$ORIGIN casa.test.'], 'casa.zone')
    await importZone('t', 'casa.test', { archivo }, {
      overwrite: true,
      overwriteZone: false,
      overwriteSoaSerial: false,
    })
    // The switches travel in the QUERY, not in the body (zone.js:1287).
    expect(spy.mock.calls[0][0]).toContain('zones/import?')
    expect(spy.mock.calls[0][0]).toContain('overwrite=true')
    expect(spy.mock.calls[0][0]).toContain('overwriteZone=false')
    expect(spy.mock.calls[0][1]?.file?.field).toBe('fileImportZone')
  })

  it('importing by pasting the text goes as text/plain, not as multipart', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await importZone('t', 'casa.test', { text: '@ 3600 IN A 10.0.0.1' }, {
      overwrite: false,
      overwriteZone: true,
      overwriteSoaSerial: false,
    })
    expect(spy.mock.calls[0][1]?.text).toBe('@ 3600 IN A 10.0.0.1')
    expect(spy.mock.calls[0][1]?.file).toBeUndefined()
  })

  it('exporting a zone goes through the single-use token and WITHOUT `ts`', async () => {
    // zone.js:1322 does not add the cache-buster that the log downloads and the
    // settings backup do carry. The URL has to come out the same.
    const spy = vi.spyOn(user, 'openDownload').mockResolvedValue({ ok: true })
    await exportZone('t', 'casa.test')
    expect(spy).toHaveBeenCalledWith('t', 'zones/export', { zone: 'casa.test', node: '' })
  })

  it('options/get asks for the available catalogs in the same call', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ name: 'casa.test' }))
    await getZoneOptions('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('zones/options/get')
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ includeAvailableCatalogZoneNames: 'true' })
  })

  it('permissions/get asks for users and groups, and tolerates absent lists', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ section: 'Zones' }))
    const r = await getZonePermissions('t', 'casa.test')
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ includeUsersAndGroups: 'true' })
    expect(r).toMatchObject({ userPermissions: [], groupPermissions: [] })
  })

  it('the permissions serialise as name|view|modify|delete per row', () => {
    expect(
      serializePermissions([
        { name: 'admin', canView: true, canModify: true, canDelete: false },
        { name: 'ana', canView: true, canModify: false, canDelete: false },
      ]),
    ).toBe('admin|true|true|false|ana|true|false|false')
  })

  it('an empty permissions table serialises as an empty string', () => {
    expect(serializePermissions([])).toBe('')
  })

  it('permissions/set sends both tables already serialised', async () => {
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

  it('every call carries `node`, even when it goes empty', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await convertZone('t', 'casa.test', 'Secondary')
    expect(spy.mock.calls[0][1]?.body).toHaveProperty('node', '')
  })
})
