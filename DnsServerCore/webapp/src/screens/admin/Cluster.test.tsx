import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Cluster } from './Cluster'
import * as client from '../../api/client'
import { CLUSTER_PRIMARIO, CLUSTER_SECUNDARIO, CLUSTER_SIN_INICIAR } from './admin.fixture'
import type { ClusterState } from '../../api/admin-cluster'
import { elegir, opcionesDe } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

/*
VERIFICATION NOTICE: the development environment is a single instance, so the
cluster never gets initialised and these tests are the only coverage eight of the
twelve endpoints have. The responses are built against `WebServiceClusterApi.cs`,
not observed live.
*/

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(state: ClusterState = CLUSTER_SIN_INICIAR) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/cluster/state') {
      return ok({
        response: { ...state, serverIpAddresses: ['10.0.0.1', '10.0.0.10'] },
        server: 'x',
      })
    }
    return ok({ response: state, server: 'x' })
  })
}

const props = { token: 'tok', cluster: null, onCluster: vi.fn(), onAviso: vi.fn() }

describe('Cluster — not initialised', () => {
  it('it only offers initialising: no Resync, no Options, no Leave, no Delete', async () => {
    servidor()
    render(<Cluster {...props} />)

    expect(await screen.findByText('Cluster Not Initialized')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'New Cluster' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Join Cluster' })).toBeInTheDocument()
    for (const n of ['Resync', 'Options', 'Leave Cluster', 'Delete Cluster']) {
      expect(screen.queryByRole('button', { name: n })).not.toBeInTheDocument()
    }
  })

  it('it does not draw the node selector', async () => {
    servidor()
    render(<Cluster {...props} />)
    await screen.findByText('Cluster Not Initialized')
    expect(screen.queryByLabelText('Cluster Node')).not.toBeInTheDocument()
  })

  it('a response without `clusterNodes` does not break the screen', async () => {
    servidor({ version: '15.4', dnsServerDomain: 'x', clusterInitialized: false })
    render(<Cluster {...props} />)
    expect(await screen.findByText('Cluster Not Initialized')).toBeInTheDocument()
  })
})

describe('Cluster — inicializar uno nuevo', () => {
  async function abrir() {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Cluster {...props} />)
    await user.click(await screen.findByRole('button', { name: 'New Cluster' }))
    await screen.findByLabelText('Cluster Domain')
    return { user, spy }
  }

  it('it requires the domain first and then some IP', async () => {
    const { user, spy } = await abrir()
    const button = screen.getByRole('button', { name: 'Initialize' })

    await user.click(button)
    expect(screen.getByText('Please enter the Cluster domain name.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Cluster Domain'), 'micluster.test')
    await user.click(button)
    expect(screen.getByText('Please enter a Primary node IP address.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/init')).toBeUndefined()
  })

  it('\"Quick Add\" appends the chosen IP to the end of the list', async () => {
    const { user } = await abrir()
    await elegir(user, screen.getByLabelText('Quick Add'), '10.0.0.1')
    expect(screen.getByLabelText('Primary Node IP Addresses')).toHaveValue('10.0.0.1\n')
  })

  it('\"Quick Add\" compares by SUBSTRING, which is the upstream bug being replicated', async () => {
    const { user } = await abrir()
    const area = screen.getByLabelText('Primary Node IP Addresses')
    await elegir(user, screen.getByLabelText('Quick Add'), '10.0.0.10')
    // With `10.0.0.10` already in the list, `indexOf('10.0.0.1')` finds it inside
    // and upstream takes the IP as added: `10.0.0.1` does NOT go in. The behaviour
    // is replicated, not the intent.
    await elegir(user, screen.getByLabelText('Quick Add'), '10.0.0.1')
    expect(area).toHaveValue('10.0.0.10\n')
  })

  it('it sends domain and IP already cleaned, and without `node`', async () => {
    const { user, spy } = await abrir()
    await user.type(screen.getByLabelText('Cluster Domain'), 'micluster.test')
    await user.type(screen.getByLabelText('Primary Node IP Addresses'), '10.0.0.1\n10.0.0.2\n')
    await user.click(screen.getByRole('button', { name: 'Initialize' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/init')?.[1]).toEqual({
      token: 'tok',
      body: { clusterDomain: 'micluster.test', primaryNodeIpAddresses: '10.0.0.1,10.0.0.2' },
    })
  })

  it('with the cluster already up, initialising another is not offered', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')
    // With the cluster already up the button is not even offered.
    expect(screen.queryByRole('button', { name: 'New Cluster' })).not.toBeInTheDocument()
  })
})

describe('Cluster — unirse a uno existente', () => {
  async function abrir() {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Cluster {...props} />)
    await user.click(await screen.findByRole('button', { name: 'Join Cluster' }))
    await screen.findByLabelText('Primary Node URL')
    return { user, spy }
  }

  it('the user comes filled in with \"admin\" and the OTP is not visible yet', async () => {
    const { user } = await abrir()
    expect(screen.getByLabelText('Primary Node Username')).toHaveValue('admin')
    expect(screen.queryByLabelText('Primary Node OTP')).not.toBeInTheDocument()
    expect(user).toBeTruthy()
  })

  it('the validation order is IP, URL, user and password', async () => {
    const { user, spy } = await abrir()
    const button = screen.getByRole('button', { name: 'Join' })

    await user.click(button)
    expect(screen.getByText('Please select a Secondary node IP address.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Secondary Node IP Addresses'), '10.0.0.3\n')
    await user.click(button)
    expect(screen.getByText('Please enter the Primary node URL.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Primary Node URL'), 'https://ns1.test')
    await user.clear(screen.getByLabelText('Primary Node Username'))
    await user.click(button)
    expect(screen.getByText('Please enter the Primary node admin username.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Primary Node Username'), 'admin')
    await user.click(button)
    expect(screen.getByText('Please enter the Primary node admin password.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/initJoin')).toBeUndefined()
  })

  it('it sends the seven fields by POST', async () => {
    const { user, spy } = await abrir()
    await user.type(screen.getByLabelText('Secondary Node IP Addresses'), '10.0.0.3\n')
    await user.type(screen.getByLabelText('Primary Node URL'), 'https://ns1.test')
    await user.type(screen.getByLabelText('Primary Node Password'), 'secreta')
    await user.click(screen.getByRole('button', { name: 'Join' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/initJoin')?.[1]).toEqual({
      token: 'tok',
      method: 'POST',
      body: {
        secondaryNodeIpAddresses: '10.0.0.3',
        primaryNodeUrl: 'https://ns1.test',
        primaryNodeIpAddress: '',
        ignoreCertificateErrors: 'false',
        primaryNodeUsername: 'admin',
        primaryNodePassword: 'secreta',
        primaryNodeTotp: '',
      },
    })
  })

  it('if the primary asks for the second factor, the OTP appears and the password locks', async () => {
    vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
      if (path === 'admin/cluster/state') {
        return ok({ response: { ...CLUSTER_SIN_INICIAR, serverIpAddresses: [] }, server: 'x' })
      }
      return { kind: 'two-factor-required' as const }
    })
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await user.click(await screen.findByRole('button', { name: 'Join Cluster' }))
    await user.type(await screen.findByLabelText('Secondary Node IP Addresses'), '10.0.0.3\n')
    await user.type(screen.getByLabelText('Primary Node URL'), 'https://ns1.test')
    await user.type(screen.getByLabelText('Primary Node Password'), 'secreta')
    await user.click(screen.getByRole('button', { name: 'Join' }))

    expect(await screen.findByLabelText('Primary Node OTP')).toBeInTheDocument()
    expect(screen.getByLabelText('Primary Node Password')).toBeDisabled()

    // And from there on the OTP is indeed required.
    await user.click(screen.getByRole('button', { name: 'Join' }))
    expect(screen.getByText("Please enter the Primary node admin user's OTP.")).toBeInTheDocument()
  })
})

describe('Cluster — seen from the PRIMARY node', () => {
  it('it offers Options and Delete Cluster, but neither Resync nor Leave', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    expect(screen.getByRole('button', { name: 'Options' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete Cluster' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resync' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Leave Cluster' })).not.toBeInTheDocument()
  })

  it('it draws the node selector with the type lowercased', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')
    const user = userEvent.setup()
    expect(await opcionesDe(user, screen.getByLabelText('Cluster Node'))).toEqual([
      'ns1.micluster.test (primary)',
      'ns2.micluster.test (secondary)',
    ])
  })

  it('it can edit itself and remove the secondary, and nothing else', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    expect(screen.getAllByRole('button', { name: 'Edit Node' })).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Actions for ns2.micluster.test' }))
    expect(await screen.findByRole('button', { name: 'Remove Node' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Promote To Primary' })).not.toBeInTheDocument()
  })

  it('\"Force Remove Node\" changes the ENDPOINT, not a parameter', async () => {
    const spy = servidor(CLUSTER_PRIMARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Actions for ns2.micluster.test' }))
    await user.click(await screen.findByRole('button', { name: 'Remove Node' }))
    await user.click(screen.getByRole('button', { name: 'Remove' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/removeSecondary')?.[1]).toEqual(
      { token: 'tok', body: { secondaryNodeId: '2', node: '' } },
    )

    await user.click(screen.getByRole('button', { name: 'Actions for ns2.micluster.test' }))
    await user.click(await screen.findByRole('button', { name: 'Remove Node' }))
    await user.click(screen.getByLabelText('Force Remove Node'))
    await user.click(screen.getByRole('button', { name: 'Remove' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/deleteSecondary')?.[1]).toEqual(
      { token: 'tok', body: { secondaryNodeId: '2', node: '' } },
    )
  })

  it('deleting the cluster sends the flag and alerts with the upstream literal', async () => {
    const onAviso = vi.fn()
    const spy = servidor(CLUSTER_PRIMARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} onAviso={onAviso} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Delete Cluster' }))
    await user.click(screen.getByLabelText('Force Delete Cluster'))
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/delete')?.[1]).toEqual({
      token: 'tok',
      body: { forceDelete: 'true', node: '' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Cluster Deleted!',
      text: 'Cluster was deleted successfully.',
    })
  })

  it('editing the node itself requires some IP and sends the cleaned list', async () => {
    const spy = servidor(CLUSTER_PRIMARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Edit Node' }))
    const area = await screen.findByLabelText('Node IP Addresses')
    expect(area).toHaveValue('10.0.0.1\n')

    await user.clear(area)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByText('Please enter a node IP address.')).toBeInTheDocument()

    await user.type(area, '10.0.0.5\n10.0.0.6\n')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/updateIpAddress')?.[1]).toEqual({
      token: 'tok',
      body: { ipAddresses: '10.0.0.5,10.0.0.6', node: '' },
    })
  })
})

describe('Cluster — seen from a SECONDARY node', () => {
  it('it offers Resync, Options and Leave Cluster, but not Delete Cluster', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    expect(screen.getByRole('button', { name: 'Resync' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Options' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Leave Cluster' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete Cluster' })).not.toBeInTheDocument()
  })

  it('it can promote itself and edit the record of the primary', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    expect(screen.getAllByRole('button', { name: 'Edit Node' })).toHaveLength(2)
    await userEvent.click(screen.getByRole('button', { name: /^Actions for / }))
    expect(await screen.findByRole('button', { name: 'Promote To Primary' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove Node' })).not.toBeInTheDocument()
  })

  it('the resync asks for confirmation and warns that the Logs must be checked', async () => {
    const onAviso = vi.fn()
    const spy = servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} onAviso={onAviso} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Resync' }))
    expect(
      screen.getByText(/Are you sure you want to resync the Cluster config\?/),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/resync')).toBeUndefined()

    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Resync' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/resync')?.[1]).toEqual({
      token: 'tok',
      body: { node: '' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Resync Triggered!',
      text: 'A full config resync was triggered successfully. Please check the Logs for confirmation.',
    })
  })

  it('leaving the cluster sends the flag to the secondary endpoint', async () => {
    const spy = servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Leave Cluster' }))
    await user.click(screen.getByRole('button', { name: 'Leave' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/leave')?.[1]).toEqual({
      token: 'tok',
      body: { forceLeave: 'false', node: '' },
    })
  })

  it('promoting sends `forceDeletePrimary` and alerts with the upstream literal', async () => {
    const onAviso = vi.fn()
    const spy = servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} onAviso={onAviso} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: /^Actions for / }))
    await user.click(await screen.findByRole('button', { name: 'Promote To Primary' }))
    await user.click(screen.getByLabelText('Force Delete Current Primary Node'))
    await user.click(screen.getByRole('button', { name: 'Promote' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/promote')?.[1]).toEqual({
      token: 'tok',
      body: { forceDeletePrimary: 'true', node: '' },
    })
    expect(onAviso).toHaveBeenCalledWith({
      type: 'success',
      title: 'Promoted!',
      text: 'The selected node was successfully promoted to Primary node in the Cluster.',
    })
  })

  it('editing the record of the primary requires the URL and allows an empty IP list', async () => {
    const spy = servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getAllByRole('button', { name: 'Edit Node' })[0])
    const url = await screen.findByLabelText('Primary Node URL')

    await user.clear(url)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByText('Please enter the Primary node URL.')).toBeInTheDocument()

    await user.type(url, 'https://ns1.micluster.test')
    await user.clear(screen.getByLabelText('Primary Node IP Addresses (Optional)'))
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/secondary/updatePrimary')?.[1]).toEqual(
      {
        token: 'tok',
        body: {
          primaryNodeUrl: 'https://ns1.micluster.test',
          primaryNodeIpAddresses: '',
          node: '',
        },
      },
    )
  })
})

describe('Cluster — the options', () => {
  it('from the primary they can be touched and saved, in the order of upstream', async () => {
    const spy = servidor(CLUSTER_PRIMARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Options' }))

    const hb = await screen.findByLabelText('Heartbeat Refresh Interval')
    expect(hb).toHaveValue(30)
    expect(screen.getByLabelText('Cluster Domain')).toBeDisabled()

    await user.clear(hb)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(
      screen.getByText('Please enter a value for Heartbeat Refresh Interval.'),
    ).toBeInTheDocument()

    await user.type(hb, '45')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/setOptions')?.[1]).toEqual({
      token: 'tok',
      body: {
        heartbeatRefreshIntervalSeconds: '45',
        heartbeatRetryIntervalSeconds: '10',
        configRefreshIntervalSeconds: '900',
        configRetryIntervalSeconds: '60',
        node: '',
      },
    })
  })

  it('from a secondary the intervals come out locked and with no save button', async () => {
    servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Options' }))

    expect(await screen.findByLabelText('Heartbeat Refresh Interval')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })
})

describe('Cluster — the node table', () => {
  it('the node itself shows no \"Last Seen\", and a secondary looking at itself does show \"Last Synced\"', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    const rows = screen.getAllByRole('row')
    // The row of the node itself (the secondary) is the last one.
    const own = rows[rows.length - 1]
    expect(own).toHaveTextContent('Self')
    // Without "Last Seen" (it is the node itself) but WITH "Last Synced", which
    // only exists for a secondary looking at itself.
    expect(within(own).getAllByText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)).toHaveLength(2)
  })

  it('an unknown type or state comes out as \"Unknown\" instead of blank', async () => {
    servidor({
      ...CLUSTER_PRIMARIO,
      clusterNodes: [
        { ...CLUSTER_PRIMARIO.clusterNodes![0], type: 'Marciano', state: 'Raro' },
      ],
    })
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 1')
    expect(screen.getAllByText('Unknown')).toHaveLength(2)
  })
})
