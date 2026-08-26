import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  buildUpload,
  downloadAndInstall,
  downloadAndUpdate,
  etiquetasDnsApp,
  getAppConfig,
  installApp,
  listApps,
  listStoreApps,
  setAppConfig,
  uninstallApp,
  updateApp,
} from './apps'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())

function espiar() {
  return vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
}

describe('apps — endpoints de lectura', () => {
  it('lista las instaladas por `apps/list`, con el nodo del clúster', async () => {
    // `node` lo manda upstream también aquí (zone.js:4440, al cargar los
    // nombres de app del modal de registro). Con una sola instancia va vacío.
    const spy = espiar()
    await listApps('t')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/list')
    expect(call).toBeDefined()
    expect(call![1]?.body).toEqual({ node: '' })
  })

  it('lista la tienda por `apps/listStoreApps`', async () => {
    const spy = espiar()
    await listStoreApps('t')
    expect(spy.mock.calls.find((c) => c[0] === 'apps/listStoreApps')).toBeDefined()
  })

  /*
  El `node` es el nodo primario del clúster: upstream lee SIEMPRE la config del
  primario para no leer una copia sin propagar (apps.js:460). Sin clúster, lo
  que se manda es la cadena vacía, y el servidor la ignora.
  */
  it('pide la config con `name` y con `node`, vacío por defecto', async () => {
    const spy = espiar()
    await getAppConfig('t', 'NO DATA')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/get')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', node: '' })
  })

  it('respeta el nodo cuando se le pasa uno', async () => {
    const spy = espiar()
    await getAppConfig('t', 'NO DATA', 'primario')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/get')
    expect(call![1]?.body?.node).toBe('primario')
  })
})

describe('apps — endpoints de escritura', () => {
  it('instala desde la tienda con nombre y url', async () => {
    const spy = espiar()
    await downloadAndInstall('t', 'NO DATA', 'https://x/y.zip')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/downloadAndInstall')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', url: 'https://x/y.zip' })
  })

  it('actualiza desde la tienda con nombre y url', async () => {
    const spy = espiar()
    await downloadAndUpdate('t', 'NO DATA', 'https://x/y.zip')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/downloadAndUpdate')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', url: 'https://x/y.zip' })
  })

  it('desinstala con el nombre', async () => {
    const spy = espiar()
    await uninstallApp('t', 'NO DATA')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/uninstall')
    expect(call![1]?.body).toEqual({ name: 'NO DATA' })
  })

  it('guarda la config por POST', async () => {
    const spy = espiar()
    await setAppConfig('t', 'NO DATA', '{"a":1}')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/set')
    expect(call![1]?.method).toBe('POST')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', config: '{"a":1}' })
  })
})

/*
Subida multipart. El cliente todavía no la soporta, así que aquí sólo se
comprueba lo que SÍ se puede comprobar: la ruta y la forma del FormData.
*/
describe('apps — subida de zip', () => {
  it('arma la petición de instalar con el nombre en la ruta y el zip en el form', () => {
    const file = new File(['zip'], 'app.zip')
    const req = buildUpload('apps/install', 'NO DATA', file)
    expect(req.path).toBe('apps/install?name=NO+DATA')
    expect(req.form.get('fileAppZip')).toBe(file)
  })

  it('arma la de actualizar contra `apps/update`', () => {
    const file = new File(['zip'], 'app.zip')
    expect(buildUpload('apps/update', 'A B', file).path).toBe('apps/update?name=A+B')
  })

  it('installApp sube el zip como multipart y con el nombre en la query', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} } as never)
    const zip = new File(['PK'], 'app.zip', { type: 'application/zip' })
    await installApp('t', 'NO DATA', zip)
    const [path, opts] = spy.mock.calls[0]
    // El servidor da 404 por GET, así que el cliente fuerza POST al ver `form`.
    expect(path).toBe('apps/install?name=NO+DATA')
    expect(opts?.form).toBeInstanceOf(FormData)
    expect((opts?.form as FormData).get('fileAppZip')).toBeInstanceOf(File)
  })

  it('updateApp sube el zip igual, contra apps/update', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} } as never)
    await updateApp('t', 'Split Horizon', new File(['PK'], 'app.zip'))
    expect(spy.mock.calls[0][0]).toBe('apps/update?name=Split+Horizon')
    expect(spy.mock.calls[0][1]?.form).toBeInstanceOf(FormData)
  })

})

describe('etiquetasDnsApp', () => {
  const base = {
    classPath: 'X.App',
    description: '',
    isAppRecordRequestHandler: false,
    recordDataTemplate: null,
    isRequestController: false,
    isAuthoritativeRequestHandler: false,
    isRequestBlockingHandler: false,
    isQueryLogger: false,
    isQueryLogs: false,
    isPostProcessor: false,
  }

  it('sin ninguna capacidad, la etiqueta es «Generic»', () => {
    expect(etiquetasDnsApp(base)).toEqual(['Generic'])
  })

  it('respeta el orden de upstream y no añade «Generic» si hay alguna', () => {
    expect(
      etiquetasDnsApp({
        ...base,
        isAppRecordRequestHandler: true,
        isQueryLogger: true,
        isPostProcessor: true,
      }),
    ).toEqual(['APP Record', 'Query Logger', 'Post Processor'])
  })

  it('cubre las siete capacidades con los textos de upstream', () => {
    expect(
      etiquetasDnsApp({
        ...base,
        isAppRecordRequestHandler: true,
        isRequestController: true,
        isAuthoritativeRequestHandler: true,
        isRequestBlockingHandler: true,
        isQueryLogger: true,
        isQueryLogs: true,
        isPostProcessor: true,
      }),
    ).toEqual([
      'APP Record',
      'Access Control',
      'Authoritative',
      'Blocking',
      'Query Logger',
      'Query Logs',
      'Post Processor',
    ])
  })
})
