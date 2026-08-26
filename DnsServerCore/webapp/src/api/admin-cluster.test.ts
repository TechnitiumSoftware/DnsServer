import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from './client'
import {
  deleteCluster,
  deleteSecondaryNode,
  getClusterState,
  initCluster,
  initJoinCluster,
  leaveCluster,
  primaryNodeName,
  promoteToPrimary,
  removeSecondaryNode,
  resyncCluster,
  setClusterOptions,
  updateIpAddress,
  updatePrimaryNode,
  type ClusterState,
} from './admin-cluster'

afterEach(() => vi.restoreAllMocks())

function espia() {
  return vi
    .spyOn(client, 'apiRequest')
    .mockResolvedValue({ kind: 'ok', data: { response: {}, server: 's' } })
}

describe('cluster — estado', () => {
  it('sin opciones no manda ningún parámetro', async () => {
    const spy = espia()
    await getClusterState('tok')
    expect(spy).toHaveBeenCalledWith('admin/cluster/state', { token: 'tok', body: {} })
  })

  it('pide las IP del servidor sólo cuando se le dice', async () => {
    const spy = espia()
    await getClusterState('tok', { node: 'ns1', includeServerIpAddresses: true })
    expect(spy.mock.calls[0][1]).toEqual({
      token: 'tok',
      body: { includeServerIpAddresses: 'true', node: 'ns1' },
    })
  })
})

describe('cluster — inicialización', () => {
  it('`init` no manda `node`: el cluster se crea en este servidor', async () => {
    const spy = espia()
    await initCluster('tok', 'micluster.tld', '10.0.0.1,10.0.0.2')
    expect(spy).toHaveBeenCalledWith('admin/cluster/init', {
      token: 'tok',
      body: { clusterDomain: 'micluster.tld', primaryNodeIpAddresses: '10.0.0.1,10.0.0.2' },
    })
  })

  it('`initJoin` va por POST con los siete campos', async () => {
    const spy = espia()
    await initJoinCluster('tok', {
      secondaryNodeIpAddresses: '10.0.0.3',
      primaryNodeUrl: 'https://ns1.test',
      primaryNodeIpAddress: '',
      ignoreCertificateErrors: 'false',
      primaryNodeUsername: 'admin',
      primaryNodePassword: 'x',
      primaryNodeTotp: '',
    })
    expect(spy.mock.calls[0][0]).toBe('admin/cluster/initJoin')
    expect(spy.mock.calls[0][1]?.method).toBe('POST')
    expect(Object.keys(spy.mock.calls[0][1]?.body ?? {})).toHaveLength(7)
  })
})

describe('cluster — acciones sobre nodos', () => {
  it('cada acción va a su endpoint con su nodo', async () => {
    const spy = espia()
    await updateIpAddress('tok', '10.0.0.9', 'ns1')
    await updatePrimaryNode('tok', 'https://p.test', '10.0.0.1', 'ns2')
    await removeSecondaryNode('tok', '7', 'ns1')
    await deleteSecondaryNode('tok', '7', 'ns1')
    await promoteToPrimary('tok', true, 'ns2')
    await leaveCluster('tok', false, 'ns2')
    await deleteCluster('tok', true, 'ns1')
    await resyncCluster('tok', 'ns2')
    await setClusterOptions(
      'tok',
      {
        heartbeatRefreshIntervalSeconds: '30',
        heartbeatRetryIntervalSeconds: '10',
        configRefreshIntervalSeconds: '900',
        configRetryIntervalSeconds: '60',
      },
      'ns1',
    )

    expect(spy.mock.calls.map((c) => c[0])).toEqual([
      'admin/cluster/updateIpAddress',
      'admin/cluster/secondary/updatePrimary',
      'admin/cluster/primary/removeSecondary',
      'admin/cluster/primary/deleteSecondary',
      'admin/cluster/secondary/promote',
      'admin/cluster/secondary/leave',
      'admin/cluster/primary/delete',
      'admin/cluster/secondary/resync',
      'admin/cluster/primary/setOptions',
    ])
  })

  it('las banderas viajan como cadena `true` / `false`', async () => {
    const spy = espia()
    await promoteToPrimary('tok', true, 'ns2')
    await leaveCluster('tok', false, 'ns2')
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/promote')?.[1]?.body).toEqual({
      forceDeletePrimary: 'true',
      node: 'ns2',
    })
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/leave')?.[1]?.body).toEqual({
      forceLeave: 'false',
      node: 'ns2',
    })
  })

  it('`setOptions` manda los cuatro intervalos más el nodo', async () => {
    const spy = espia()
    await setClusterOptions(
      'tok',
      {
        heartbeatRefreshIntervalSeconds: '30',
        heartbeatRetryIntervalSeconds: '10',
        configRefreshIntervalSeconds: '900',
        configRetryIntervalSeconds: '60',
      },
      'ns1',
    )
    expect(spy.mock.calls[0][1]?.body).toEqual({
      heartbeatRefreshIntervalSeconds: '30',
      heartbeatRetryIntervalSeconds: '10',
      configRefreshIntervalSeconds: '900',
      configRetryIntervalSeconds: '60',
      node: 'ns1',
    })
  })
})

describe('primaryNodeName', () => {
  const nodo = (name: string, type: string) => ({
    id: 1,
    name,
    url: 'https://x',
    ipAddresses: [],
    type,
    state: 'Connected',
  })

  it('sin estado devuelve cadena vacía', () => {
    expect(primaryNodeName(null)).toBe('')
  })

  it('sin cluster inicializado devuelve cadena vacía aunque haya nodos', () => {
    const s = {
      version: '15.4',
      dnsServerDomain: 'x',
      clusterInitialized: false,
      clusterNodes: [nodo('ns1', 'Primary')],
    } as ClusterState
    expect(primaryNodeName(s)).toBe('')
  })

  it('devuelve el nombre del nodo primario', () => {
    const s = {
      version: '15.4',
      dnsServerDomain: 'x',
      clusterInitialized: true,
      clusterNodes: [nodo('ns2', 'Secondary'), nodo('ns1', 'Primary')],
    } as ClusterState
    expect(primaryNodeName(s)).toBe('ns1')
  })
})
