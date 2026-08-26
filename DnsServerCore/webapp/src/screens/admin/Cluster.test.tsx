import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Cluster } from './Cluster'
import * as client from '../../api/client'
import { CLUSTER_PRIMARIO, CLUSTER_SECUNDARIO, CLUSTER_SIN_INICIAR } from './admin.fixture'
import type { ClusterState } from '../../api/admin-cluster'

afterEach(() => vi.restoreAllMocks())

/*
AVISO DE VERIFICACIÓN: el entorno de desarrollo es una sola instancia, así que el
cluster nunca llega a inicializarse y estas pruebas son la única cobertura que
tienen ocho de los doce endpoints. Las respuestas están construidas contra
`WebServiceClusterApi.cs`, no observadas en vivo.
*/

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(estado: ClusterState = CLUSTER_SIN_INICIAR) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/cluster/state') {
      return ok({
        response: { ...estado, serverIpAddresses: ['10.0.0.1', '10.0.0.10'] },
        server: 'x',
      })
    }
    return ok({ response: estado, server: 'x' })
  })
}

const props = { token: 'tok', cluster: null, onCluster: vi.fn(), onAviso: vi.fn() }

describe('Cluster — sin inicializar', () => {
  it('sólo ofrece inicializar: ni Resync, ni Options, ni Leave, ni Delete', async () => {
    servidor()
    render(<Cluster {...props} />)

    expect(await screen.findByText('Cluster Not Initialized')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'New Cluster' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Join Cluster' })).toBeInTheDocument()
    for (const n of ['Resync', 'Options', 'Leave Cluster', 'Delete Cluster']) {
      expect(screen.queryByRole('button', { name: n })).not.toBeInTheDocument()
    }
  })

  it('no pinta el selector de nodo', async () => {
    servidor()
    render(<Cluster {...props} />)
    await screen.findByText('Cluster Not Initialized')
    expect(screen.queryByLabelText('Cluster Node')).not.toBeInTheDocument()
  })

  it('una respuesta sin `clusterNodes` no rompe la pantalla', async () => {
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

  it('exige primero el dominio y después alguna IP', async () => {
    const { user, spy } = await abrir()
    const boton = screen.getByRole('button', { name: 'Initialize' })

    await user.click(boton)
    expect(screen.getByText('Please enter the Cluster domain name.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Cluster Domain'), 'micluster.test')
    await user.click(boton)
    expect(screen.getByText('Please enter a Primary node IP address.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/init')).toBeUndefined()
  })

  it('«Quick Add» añade la IP elegida al final de la lista', async () => {
    const { user } = await abrir()
    await user.selectOptions(screen.getByLabelText('Quick Add'), '10.0.0.1')
    expect(screen.getByLabelText('Primary Node IP Addresses')).toHaveValue('10.0.0.1\n')
  })

  it('«Quick Add» compara por SUBCADENA, que es el bug de upstream que se replica', async () => {
    const { user } = await abrir()
    const area = screen.getByLabelText('Primary Node IP Addresses')
    await user.selectOptions(screen.getByLabelText('Quick Add'), '10.0.0.10')
    // Con `10.0.0.10` ya en la lista, `indexOf('10.0.0.1')` la encuentra dentro
    // y upstream da la IP por añadida: `10.0.0.1` NO entra. Se replica el
    // comportamiento, no la intención.
    await user.selectOptions(screen.getByLabelText('Quick Add'), '10.0.0.1')
    expect(area).toHaveValue('10.0.0.10\n')
  })

  it('manda dominio e IP ya limpiadas, y sin `node`', async () => {
    const { user, spy } = await abrir()
    await user.type(screen.getByLabelText('Cluster Domain'), 'micluster.test')
    await user.type(screen.getByLabelText('Primary Node IP Addresses'), '10.0.0.1\n10.0.0.2\n')
    await user.click(screen.getByRole('button', { name: 'Initialize' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/init')?.[1]).toEqual({
      token: 'tok',
      body: { clusterDomain: 'micluster.test', primaryNodeIpAddresses: '10.0.0.1,10.0.0.2' },
    })
  })

  it('con el cluster ya montado no se ofrece inicializar otro', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')
    // Con el cluster ya montado el botón ni siquiera se ofrece.
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

  it('el usuario viene relleno con «admin» y el OTP no se ve todavía', async () => {
    const { user } = await abrir()
    expect(screen.getByLabelText('Primary Node Username')).toHaveValue('admin')
    expect(screen.queryByLabelText('Primary Node OTP')).not.toBeInTheDocument()
    expect(user).toBeTruthy()
  })

  it('el orden de las validaciones es IP, URL, usuario y contraseña', async () => {
    const { user, spy } = await abrir()
    const boton = screen.getByRole('button', { name: 'Join' })

    await user.click(boton)
    expect(screen.getByText('Please select a Secondary node IP address.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Secondary Node IP Addresses'), '10.0.0.3\n')
    await user.click(boton)
    expect(screen.getByText('Please enter the Primary node URL.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Primary Node URL'), 'https://ns1.test')
    await user.clear(screen.getByLabelText('Primary Node Username'))
    await user.click(boton)
    expect(screen.getByText('Please enter the Primary node admin username.')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Primary Node Username'), 'admin')
    await user.click(boton)
    expect(screen.getByText('Please enter the Primary node admin password.')).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/initJoin')).toBeUndefined()
  })

  it('manda los siete campos por POST', async () => {
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

  it('si el primario pide segundo factor, aparece el OTP y se bloquea la contraseña', async () => {
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

    // Y a partir de ahí el OTP sí es obligatorio.
    await user.click(screen.getByRole('button', { name: 'Join' }))
    expect(screen.getByText("Please enter the Primary node admin user's OTP.")).toBeInTheDocument()
  })
})

describe('Cluster — visto desde el nodo PRIMARIO', () => {
  it('ofrece Options y Delete Cluster, pero no Resync ni Leave', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    expect(screen.getByRole('button', { name: 'Options' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete Cluster' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resync' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Leave Cluster' })).not.toBeInTheDocument()
  })

  it('pinta el selector de nodos con el tipo en minúsculas', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')
    const selector = screen.getByLabelText('Cluster Node')
    expect(selector).toHaveTextContent('ns1.micluster.test (primary)')
    expect(selector).toHaveTextContent('ns2.micluster.test (secondary)')
  })

  it('puede editarse a sí mismo y quitar el secundario, y nada más', async () => {
    servidor(CLUSTER_PRIMARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    expect(screen.getAllByRole('button', { name: 'Edit Node' })).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Remove Node' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Promote To Primary' })).not.toBeInTheDocument()
  })

  it('«Force Remove Node» cambia de ENDPOINT, no de parámetro', async () => {
    const spy = servidor(CLUSTER_PRIMARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Remove Node' }))
    await user.click(screen.getByRole('button', { name: 'Remove' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/removeSecondary')?.[1]).toEqual(
      { token: 'tok', body: { secondaryNodeId: '2', node: '' } },
    )

    await user.click(screen.getByRole('button', { name: 'Remove Node' }))
    await user.click(screen.getByLabelText('Force Remove Node'))
    await user.click(screen.getByRole('button', { name: 'Remove' }))
    expect(spy.mock.calls.find((c) => c[0] === 'admin/cluster/primary/deleteSecondary')?.[1]).toEqual(
      { token: 'tok', body: { secondaryNodeId: '2', node: '' } },
    )
  })

  it('borrar el cluster manda la bandera y avisa con el literal de upstream', async () => {
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

  it('editar el nodo propio exige alguna IP y manda la lista limpiada', async () => {
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

describe('Cluster — visto desde un nodo SECUNDARIO', () => {
  it('ofrece Resync, Options y Leave Cluster, pero no Delete Cluster', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    expect(screen.getByRole('button', { name: 'Resync' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Options' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Leave Cluster' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete Cluster' })).not.toBeInTheDocument()
  })

  it('puede promocionarse y editar la ficha del primario', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    expect(screen.getByRole('button', { name: 'Promote To Primary' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Edit Node' })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: 'Remove Node' })).not.toBeInTheDocument()
  })

  it('el resync pide confirmación y avisa de que hay que mirar los Logs', async () => {
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

  it('dejar el cluster manda la bandera al endpoint del secundario', async () => {
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

  it('promocionar manda `forceDeletePrimary` y avisa con el literal de upstream', async () => {
    const onAviso = vi.fn()
    const spy = servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} onAviso={onAviso} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Promote To Primary' }))
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

  it('editar la ficha del primario exige la URL y admite lista de IP vacía', async () => {
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

describe('Cluster — las opciones', () => {
  it('desde el primario se pueden tocar y guardar, en el orden de upstream', async () => {
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

  it('desde un secundario los intervalos salen bloqueados y sin botón de guardar', async () => {
    servidor(CLUSTER_SECUNDARIO)
    const user = userEvent.setup()
    render(<Cluster {...props} />)

    await screen.findByText('Total Nodes: 2')
    await user.click(screen.getByRole('button', { name: 'Options' }))

    expect(await screen.findByLabelText('Heartbeat Refresh Interval')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })
})

describe('Cluster — la tabla de nodos', () => {
  it('el nodo propio no enseña «Last Seen», y un secundario propio sí «Last Synced»', async () => {
    servidor(CLUSTER_SECUNDARIO)
    render(<Cluster {...props} />)
    await screen.findByText('Total Nodes: 2')

    const filas = screen.getAllByRole('row')
    // La fila del nodo propio (el secundario) es la última.
    const propia = filas[filas.length - 1]
    expect(propia).toHaveTextContent('Self')
    // Sin «Last Seen» (es el nodo propio) pero CON «Last Synced», que sólo
    // existe para un secundario que se mira a sí mismo.
    expect(within(propia).getAllByText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)).toHaveLength(2)
  })

  it('un tipo o un estado desconocidos salen como «Unknown» en vez de en blanco', async () => {
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
