import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  buildUpload,
  downloadAndInstall,
  downloadAndUpdate,
  dnsAppLabels,
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

describe('apps — read endpoints', () => {
  it('it lists the installed ones through `apps/list`, with the cluster node', async () => {
    // upstream sends `node` here too (zone.js:4440, when loading the record
    // modal's app names). With a single instance it goes empty.
    const spy = espiar()
    await listApps('t')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/list')
    expect(call).toBeDefined()
    expect(call![1]?.body).toEqual({ node: '' })
  })

  it('it lists the store through `apps/listStoreApps`', async () => {
    const spy = espiar()
    await listStoreApps('t')
    expect(spy.mock.calls.find((c) => c[0] === 'apps/listStoreApps')).toBeDefined()
  })

  /*
  The `node` is the cluster's primary node: upstream ALWAYS reads the config from
  the primary so as not to read an unpropagated copy (apps.js:460). Without a
  cluster, what gets sent is the empty string, and the server ignores it.
  */
  it('it asks for the config with `name` and with `node`, empty by default', async () => {
    const spy = espiar()
    await getAppConfig('t', 'NO DATA')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/get')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', node: '' })
  })

  it('it honours the node when one is passed', async () => {
    const spy = espiar()
    await getAppConfig('t', 'NO DATA', 'primario')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/get')
    expect(call![1]?.body?.node).toBe('primario')
  })
})

describe('apps — write endpoints', () => {
  it('it installs from the store with name and url', async () => {
    const spy = espiar()
    await downloadAndInstall('t', 'NO DATA', 'https://x/y.zip')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/downloadAndInstall')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', url: 'https://x/y.zip' })
  })

  it('it updates from the store with name and url', async () => {
    const spy = espiar()
    await downloadAndUpdate('t', 'NO DATA', 'https://x/y.zip')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/downloadAndUpdate')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', url: 'https://x/y.zip' })
  })

  it('it uninstalls with the name', async () => {
    const spy = espiar()
    await uninstallApp('t', 'NO DATA')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/uninstall')
    expect(call![1]?.body).toEqual({ name: 'NO DATA' })
  })

  it('it saves the config by POST', async () => {
    const spy = espiar()
    await setAppConfig('t', 'NO DATA', '{"a":1}')
    const call = spy.mock.calls.find((c) => c[0] === 'apps/config/set')
    expect(call![1]?.method).toBe('POST')
    expect(call![1]?.body).toEqual({ name: 'NO DATA', config: '{"a":1}' })
  })
})

/*
Multipart upload. The client does not support it yet, so what is checked here is
only what CAN be checked: the path and the shape of the FormData.
*/
describe('apps — zip upload', () => {
  it('it builds the install request with the name in the path and the zip in the form', () => {
    const file = new File(['zip'], 'app.zip')
    const req = buildUpload('apps/install', 'NO DATA', file)
    expect(req.path).toBe('apps/install?name=NO+DATA')
    expect(req.form.get('fileAppZip')).toBe(file)
  })

  it('it builds the update one against `apps/update`', () => {
    const file = new File(['zip'], 'app.zip')
    expect(buildUpload('apps/update', 'A B', file).path).toBe('apps/update?name=A+B')
  })

  it('installApp uploads the zip as multipart and with the name in the query', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} } as never)
    const zip = new File(['PK'], 'app.zip', { type: 'application/zip' })
    await installApp('t', 'NO DATA', zip)
    const [path, opts] = spy.mock.calls[0]
    // The server gives a 404 by GET, so the client forces POST on seeing `form`.
    expect(path).toBe('apps/install?name=NO+DATA')
    expect(opts?.form).toBeInstanceOf(FormData)
    expect((opts?.form as FormData).get('fileAppZip')).toBeInstanceOf(File)
  })

  it('updateApp uploads the zip the same way, against apps/update', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} } as never)
    await updateApp('t', 'Split Horizon', new File(['PK'], 'app.zip'))
    expect(spy.mock.calls[0][0]).toBe('apps/update?name=Split+Horizon')
    expect(spy.mock.calls[0][1]?.form).toBeInstanceOf(FormData)
  })

})

describe('dnsAppLabels', () => {
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

  it('with no capability at all, the label is \"Generic\"', () => {
    expect(dnsAppLabels(base)).toEqual(['Generic'])
  })

  it('it honours the upstream order and does not add \"Generic\" if there is any', () => {
    expect(
      dnsAppLabels({
        ...base,
        isAppRecordRequestHandler: true,
        isQueryLogger: true,
        isPostProcessor: true,
      }),
    ).toEqual(['APP Record', 'Query Logger', 'Post Processor'])
  })

  it('it covers the seven capabilities with the upstream texts', () => {
    expect(
      dnsAppLabels({
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
