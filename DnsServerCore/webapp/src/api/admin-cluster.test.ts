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
  it('with no options it sends no parameter', async () => {
    const spy = espia()
    await getClusterState('tok')
    expect(spy).toHaveBeenCalledWith('admin/cluster/state', { token: 'tok', body: {} })
  })

  it('it asks for the server IPs only when told to', async () => {
    const spy = espia()
    await getClusterState('tok', { node: 'ns1', includeServerIpAddresses: true })
    expect(spy.mock.calls[0][1]).toEqual({
      token: 'tok',
      body: { includeServerIpAddresses: 'true', node: 'ns1' },
    })
  })
})

describe('cluster — initialisation', () => {
  it('`init` sends no `node`: the cluster is created on this server', async () => {
    const spy = espia()
    await initCluster('tok', 'micluster.tld', '10.0.0.1,10.0.0.2')
    expect(spy).toHaveBeenCalledWith('admin/cluster/init', {
      token: 'tok',
      body: { clusterDomain: 'micluster.tld', primaryNodeIpAddresses: '10.0.0.1,10.0.0.2' },
    })
  })

  it('`initJoin` goes by POST with the seven fields', async () => {
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

describe('cluster — actions on nodes', () => {
  it('each action goes to its endpoint with its node', async () => {
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

  it('the flags travel as the strings `true` / `false`', async () => {
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

  it('`setOptions` sends the four intervals plus the node', async () => {
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
  const node = (name: string, type: string) => ({
    id: 1,
    name,
    url: 'https://x',
    ipAddresses: [],
    type,
    state: 'Connected',
  })

  it('with no state it returns an empty string', () => {
    expect(primaryNodeName(null)).toBe('')
  })

  it('with the cluster uninitialised it returns an empty string even if there are nodes', () => {
    const s = {
      version: '15.4',
      dnsServerDomain: 'x',
      clusterInitialized: false,
      clusterNodes: [node('ns1', 'Primary')],
    } as ClusterState
    expect(primaryNodeName(s)).toBe('')
  })

  it('it returns the name of the primary node', () => {
    const s = {
      version: '15.4',
      dnsServerDomain: 'x',
      clusterInitialized: true,
      clusterNodes: [node('ns2', 'Secondary'), node('ns1', 'Primary')],
    } as ClusterState
    expect(primaryNodeName(s)).toBe('ns1')
  })
})
