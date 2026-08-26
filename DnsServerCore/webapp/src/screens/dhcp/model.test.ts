import { describe, expect, it } from 'vitest'
import {
  construirCuerpo,
  formularioDesdeScope,
  formularioNuevo,
  formularioVacio,
  idCelda,
  limpiarLista,
  listaATexto,
  type ScopeForm,
} from './model'
import type { DhcpScope } from '../../api/dhcp'

function form(parcial: Partial<ScopeForm> = {}): ScopeForm {
  return { ...formularioVacio(), name: 'Default', ...parcial }
}

function cuerpo(f: ScopeForm): Record<string, string> {
  const r = construirCuerpo(f)
  if ('error' in r) throw new Error(`esperaba cuerpo y salió ${r.error.title}`)
  return r.body
}

function error(f: ScopeForm) {
  const r = construirCuerpo(f)
  if (!('error' in r)) throw new Error('esperaba error y salió cuerpo')
  return r.error
}

describe('limpiarLista / listaATexto', () => {
  it('replica cleanTextList de common.js', () => {
    expect(limpiarLista('1.1.1.1\n8.8.8.8')).toBe('1.1.1.1,8.8.8.8')
    expect(limpiarLista('\n1.1.1.1\n\n\n8.8.8.8\n')).toBe('1.1.1.1,8.8.8.8')
    expect(limpiarLista('')).toBe('')
    expect(limpiarLista('\n\n\n')).toBe('')
  })

  it('no deja `\\r` sueltos: el textarea de React ya normaliza a `\\n`', () => {
    expect(limpiarLista('1.1.1.1\n8.8.8.8')).not.toContain('\r')
  })

  it('listaATexto devuelve cadena vacía cuando el servidor omite la clave', () => {
    expect(listaATexto(undefined)).toBe('')
    expect(listaATexto(['a', 'b'])).toBe('a\nb')
  })
})

describe('valores por defecto', () => {
  it('son los de clearDhcpScopeForm', () => {
    const f = formularioVacio()
    expect(f.leaseTimeDays).toBe('1')
    expect(f.leaseTimeHours).toBe('0')
    expect(f.leaseTimeMinutes).toBe('0')
    expect(f.offerDelayTime).toBe('0')
    expect(f.pingCheckTimeout).toBe('1000')
    expect(f.pingCheckRetries).toBe('2')
    expect(f.dnsTtl).toBe('900')
    expect(f.dnsUpdates).toBe(true)
    expect(f.ignoreClientIdentifierOption).toBe(true)
    expect(f.useThisDnsServer).toBe(false)
  })

  it('«Add Scope» parte del vacío pero con «Use This DNS Server» marcado', () => {
    expect(formularioNuevo().useThisDnsServer).toBe(true)
  })
})

describe('formularioDesdeScope', () => {
  const MINIMO: DhcpScope = {
    name: 'Default',
    startingAddress: '192.168.1.1',
    endingAddress: '192.168.1.254',
    subnetMask: '255.255.255.0',
    leaseTimeDays: 1,
    leaseTimeHours: 0,
    leaseTimeMinutes: 0,
    offerDelayTime: 0,
    pingCheckEnabled: false,
    pingCheckTimeout: 1000,
    pingCheckRetries: 2,
    dnsUpdates: true,
    dnsOverwriteForDynamicLease: false,
    dnsTtl: 900,
    useThisDnsServer: true,
    reservedLeases: [],
    allowOnlyReservedLeases: false,
    blockLocallyAdministeredMacAddresses: false,
    ignoreClientIdentifierOption: true,
  }

  it('sobrevive a un scope al que le faltan quince claves', () => {
    const f = formularioDesdeScope(MINIMO)
    expect(f.domainName).toBe('')
    expect(f.domainSearchList).toBe('')
    expect(f.routerAddress).toBe('')
    expect(f.staticRoutes).toEqual([])
    expect(f.exclusions).toEqual([])
    expect(f.reservedLeases).toEqual([])
  })

  it('guarda el nombre original en `oldName`, que es lo que decide el renombrado', () => {
    expect(formularioDesdeScope(MINIMO).oldName).toBe('Default')
  })

  it('un `hostName` o un `comments` nulos de una reserva llegan como cadena vacía', () => {
    const f = formularioDesdeScope({
      ...MINIMO,
      reservedLeases: [
        { hostName: null, hardwareAddress: 'AA-BB', address: '192.168.1.5', comments: null },
      ],
    })
    expect(f.reservedLeases[0]).toEqual({
      hostName: '',
      hardwareAddress: 'AA-BB',
      address: '192.168.1.5',
      comments: '',
    })
  })
})

describe('construirCuerpo — nombre y renombrado', () => {
  it('un scope nuevo NO manda `newName`', () => {
    const b = cuerpo(form({ oldName: '', name: 'Nuevo' }))
    expect(b.name).toBe('Nuevo')
    expect(b).not.toHaveProperty('newName')
  })

  it('editar sin tocar el nombre tampoco manda `newName`', () => {
    const b = cuerpo(form({ oldName: 'Default', name: 'Default' }))
    expect(b.name).toBe('Default')
    expect(b).not.toHaveProperty('newName')
  })

  it('renombrar manda el nombre VIEJO en `name` y el nuevo en `newName`', () => {
    const b = cuerpo(form({ oldName: 'Default', name: 'Casa' }))
    expect(b.name).toBe('Default')
    expect(b.newName).toBe('Casa')
  })
})

describe('construirCuerpo — servidores DNS', () => {
  it('con «Use This DNS Server» marcado NO se manda `dnsServers`', () => {
    const b = cuerpo(form({ useThisDnsServer: true, dnsServers: '1.1.1.1' }))
    expect(b.useThisDnsServer).toBe('true')
    expect(b).not.toHaveProperty('dnsServers')
  })

  it('sin marcar, `dnsServers` viaja como lista separada por comas', () => {
    const b = cuerpo(form({ useThisDnsServer: false, dnsServers: '1.1.1.1\n8.8.8.8' }))
    expect(b.dnsServers).toBe('1.1.1.1,8.8.8.8')
  })
})

describe('construirCuerpo — las cinco tablas', () => {
  it('serializa TODAS las celdas unidas por `|`, también entre filas', () => {
    const b = cuerpo(
      form({
        staticRoutes: [
          { destination: '10.0.0.0', subnetMask: '255.0.0.0', router: '192.168.1.1' },
          { destination: '10.1.0.0', subnetMask: '255.255.0.0', router: '192.168.1.2' },
        ],
      }),
    )
    expect(b.staticRoutes).toBe(
      '10.0.0.0|255.0.0.0|192.168.1.1|10.1.0.0|255.255.0.0|192.168.1.2',
    )
  })

  it('una tabla vacía viaja como cadena vacía', () => {
    const b = cuerpo(form())
    expect(b.staticRoutes).toBe('')
    expect(b.vendorInfo).toBe('')
    expect(b.genericOptions).toBe('')
    expect(b.exclusions).toBe('')
    expect(b.reservedLeases).toBe('')
  })

  it('el identificador de fabricante SÍ puede quedarse vacío', () => {
    const b = cuerpo(form({ vendorInfo: [{ identifier: '', information: '06:01' }] }))
    expect(b.vendorInfo).toBe('|06:01')
  })

  it('el nombre de host y los comentarios de una reserva TAMBIÉN son opcionales', () => {
    const b = cuerpo(
      form({
        reservedLeases: [
          { hostName: '', hardwareAddress: 'AA-BB', address: '192.168.1.5', comments: '' },
        ],
      }),
    )
    expect(b.reservedLeases).toBe('|AA-BB|192.168.1.5|')
  })
})

describe('construirCuerpo — avisos de validación, con sus textos literales', () => {
  it('una celda obligatoria vacía da «Missing!» y señala esa celda', () => {
    const e = error(
      form({ exclusions: [{ startingAddress: '192.168.1.1', endingAddress: '' }] }),
    )
    expect(e.title).toBe('Missing!')
    expect(e.text).toBe('Please enter a valid value in the text field in focus.')
    expect(e.focus).toBe(idCelda('exclusions', 0, 'endingAddress'))
  })

  it('una celda con `|` da «Invalid Character!»', () => {
    const e = error(
      form({ exclusions: [{ startingAddress: 'a|b', endingAddress: '192.168.1.10' }] }),
    )
    expect(e.title).toBe('Invalid Character!')
    expect(e.text).toBe(
      "Please edit the value in the text field in focus to remove '|' character.",
    )
    expect(e.focus).toBe(idCelda('exclusions', 0, 'startingAddress'))
  })

  it('dentro de una celda, primero se mira el vacío y después el `|`', () => {
    const e = error(
      form({
        exclusions: [{ startingAddress: '', endingAddress: 'a|b' }],
      }),
    )
    expect(e.title).toBe('Missing!')
  })

  it('el orden de las tablas es el de upstream: rutas antes que fabricante', () => {
    const e = error(
      form({
        staticRoutes: [{ destination: '', subnetMask: '', router: '' }],
        vendorInfo: [{ identifier: 'x', information: '' }],
      }),
    )
    expect(e.focus).toBe(idCelda('staticRoutes', 0, 'destination'))
  })

  it('…fabricante antes que opciones genéricas, y éstas antes que exclusiones', () => {
    const conFabricante = error(
      form({
        vendorInfo: [{ identifier: 'x', information: '' }],
        genericOptions: [{ code: '', value: '' }],
        exclusions: [{ startingAddress: '', endingAddress: '' }],
      }),
    )
    expect(conFabricante.focus).toBe(idCelda('vendorInfo', 0, 'information'))

    const conGenericas = error(
      form({
        genericOptions: [{ code: '', value: '' }],
        exclusions: [{ startingAddress: '', endingAddress: '' }],
      }),
    )
    expect(conGenericas.focus).toBe(idCelda('genericOptions', 0, 'code'))
  })

  it('…y exclusiones antes que reservas', () => {
    const e = error(
      form({
        exclusions: [{ startingAddress: '', endingAddress: '' }],
        reservedLeases: [
          { hostName: '', hardwareAddress: '', address: '', comments: '' },
        ],
      }),
    )
    expect(e.focus).toBe(idCelda('exclusions', 0, 'startingAddress'))
  })

  it('las filas se recorren en orden: la segunda fila mala se señala como tal', () => {
    const e = error(
      form({
        exclusions: [
          { startingAddress: '192.168.1.1', endingAddress: '192.168.1.10' },
          { startingAddress: '192.168.1.20', endingAddress: '' },
        ],
      }),
    )
    expect(e.focus).toBe(idCelda('exclusions', 1, 'endingAddress'))
  })
})

describe('construirCuerpo — los 36 parámetros', () => {
  it('manda todo el formulario, con los booleanos como cadenas', () => {
    const b = cuerpo(
      form({
        oldName: 'Default',
        startingAddress: '192.168.1.1',
        endingAddress: '192.168.1.254',
        subnetMask: '255.255.255.0',
        domainName: 'home',
        domainSearchList: 'home\nlan',
        pingCheckEnabled: true,
        ntpServerDomainNames: 'pool.ntp.org',
        capwapAcIpAddresses: '10.0.0.1\n10.0.0.2',
        tftpServerAddresses: '10.0.0.3',
        allowOnlyReservedLeases: true,
      }),
    )

    expect(b).toMatchObject({
      name: 'Default',
      startingAddress: '192.168.1.1',
      endingAddress: '192.168.1.254',
      subnetMask: '255.255.255.0',
      leaseTimeDays: '1',
      leaseTimeHours: '0',
      leaseTimeMinutes: '0',
      offerDelayTime: '0',
      pingCheckEnabled: 'true',
      pingCheckTimeout: '1000',
      pingCheckRetries: '2',
      domainName: 'home',
      domainSearchList: 'home,lan',
      dnsUpdates: 'true',
      dnsOverwriteForDynamicLease: 'false',
      dnsTtl: '900',
      serverAddress: '',
      serverHostName: '',
      bootFileName: '',
      routerAddress: '',
      useThisDnsServer: 'false',
      dnsServers: '',
      winsServers: '',
      ntpServers: '',
      ntpServerDomainNames: 'pool.ntp.org',
      capwapAcIpAddresses: '10.0.0.1,10.0.0.2',
      tftpServerAddresses: '10.0.0.3',
      allowOnlyReservedLeases: 'true',
      blockLocallyAdministeredMacAddresses: 'false',
      ignoreClientIdentifierOption: 'true',
    })
  })
})
