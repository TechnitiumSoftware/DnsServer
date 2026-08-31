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

function body(f: ScopeForm): Record<string, string> {
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
  it('it replicates cleanTextList from common.js', () => {
    expect(limpiarLista('1.1.1.1\n8.8.8.8')).toBe('1.1.1.1,8.8.8.8')
    expect(limpiarLista('\n1.1.1.1\n\n\n8.8.8.8\n')).toBe('1.1.1.1,8.8.8.8')
    expect(limpiarLista('')).toBe('')
    expect(limpiarLista('\n\n\n')).toBe('')
  })

  it('it leaves no stray `\\r`: the React textarea already normalises to `\\n`', () => {
    expect(limpiarLista('1.1.1.1\n8.8.8.8')).not.toContain('\r')
  })

  it('listaATexto returns an empty string when the server omits the key', () => {
    expect(listaATexto(undefined)).toBe('')
    expect(listaATexto(['a', 'b'])).toBe('a\nb')
  })
})

describe('default values', () => {
  it('they are the ones from clearDhcpScopeForm', () => {
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

  it('\"Add Scope\" starts from empty but with \"Use This DNS Server\" checked', () => {
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

  it('it survives a scope missing fifteen keys', () => {
    const f = formularioDesdeScope(MINIMO)
    expect(f.domainName).toBe('')
    expect(f.domainSearchList).toBe('')
    expect(f.routerAddress).toBe('')
    expect(f.staticRoutes).toEqual([])
    expect(f.exclusions).toEqual([])
    expect(f.reservedLeases).toEqual([])
  })

  it('it keeps the original name in `oldName`, which is what decides the rename', () => {
    expect(formularioDesdeScope(MINIMO).oldName).toBe('Default')
  })

  it('a null `hostName` or `comments` of a reservation arrives as an empty string', () => {
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

describe('construirCuerpo — name and rename', () => {
  it('a new scope does NOT send `newName`', () => {
    const b = body(form({ oldName: '', name: 'Nuevo' }))
    expect(b.name).toBe('Nuevo')
    expect(b).not.toHaveProperty('newName')
  })

  it('editing without touching the name does not send `newName` either', () => {
    const b = body(form({ oldName: 'Default', name: 'Default' }))
    expect(b.name).toBe('Default')
    expect(b).not.toHaveProperty('newName')
  })

  it('renaming sends the OLD name in `name` and the new one in `newName`', () => {
    const b = body(form({ oldName: 'Default', name: 'Casa' }))
    expect(b.name).toBe('Default')
    expect(b.newName).toBe('Casa')
  })
})

describe('construirCuerpo — servidores DNS', () => {
  it('with \"Use This DNS Server\" checked `dnsServers` is NOT sent', () => {
    const b = body(form({ useThisDnsServer: true, dnsServers: '1.1.1.1' }))
    expect(b.useThisDnsServer).toBe('true')
    expect(b).not.toHaveProperty('dnsServers')
  })

  it('unchecked, `dnsServers` travels as a comma-separated list', () => {
    const b = body(form({ useThisDnsServer: false, dnsServers: '1.1.1.1\n8.8.8.8' }))
    expect(b.dnsServers).toBe('1.1.1.1,8.8.8.8')
  })
})

describe('construirCuerpo — the five tables', () => {
  it('it serialises ALL the cells joined by `|`, between rows as well', () => {
    const b = body(
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

  it('an empty table travels as an empty string', () => {
    const b = body(form())
    expect(b.staticRoutes).toBe('')
    expect(b.vendorInfo).toBe('')
    expect(b.genericOptions).toBe('')
    expect(b.exclusions).toBe('')
    expect(b.reservedLeases).toBe('')
  })

  it('the vendor identifier CAN be left empty', () => {
    const b = body(form({ vendorInfo: [{ identifier: '', information: '06:01' }] }))
    expect(b.vendorInfo).toBe('|06:01')
  })

  it('the host name and the comments of a reservation are ALSO optional', () => {
    const b = body(
      form({
        reservedLeases: [
          { hostName: '', hardwareAddress: 'AA-BB', address: '192.168.1.5', comments: '' },
        ],
      }),
    )
    expect(b.reservedLeases).toBe('|AA-BB|192.168.1.5|')
  })
})

describe('construirCuerpo — validation alerts, with their literal texts', () => {
  it('an empty required cell gives \"Missing!\" and points at that cell', () => {
    const e = error(
      form({ exclusions: [{ startingAddress: '192.168.1.1', endingAddress: '' }] }),
    )
    expect(e.title).toBe('Missing!')
    expect(e.text).toBe('Please enter a valid value in the text field in focus.')
    expect(e.focus).toBe(idCelda('exclusions', 0, 'endingAddress'))
  })

  it('a cell with `|` gives \"Invalid Character!\"', () => {
    const e = error(
      form({ exclusions: [{ startingAddress: 'a|b', endingAddress: '192.168.1.10' }] }),
    )
    expect(e.title).toBe('Invalid Character!')
    expect(e.text).toBe(
      "Please edit the value in the text field in focus to remove '|' character.",
    )
    expect(e.focus).toBe(idCelda('exclusions', 0, 'startingAddress'))
  })

  it('inside a cell, empty is checked first and `|` second', () => {
    const e = error(
      form({
        exclusions: [{ startingAddress: '', endingAddress: 'a|b' }],
      }),
    )
    expect(e.title).toBe('Missing!')
  })

  it('the table order is the one of upstream: routes before vendor', () => {
    const e = error(
      form({
        staticRoutes: [{ destination: '', subnetMask: '', router: '' }],
        vendorInfo: [{ identifier: 'x', information: '' }],
      }),
    )
    expect(e.focus).toBe(idCelda('staticRoutes', 0, 'destination'))
  })

  it('…vendor before generic options, and those before exclusions', () => {
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

  it('…and exclusions before reservations', () => {
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

  it('the rows are walked in order: the second bad row is pointed at as such', () => {
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

describe('construirCuerpo — the 36 parameters', () => {
  it('it sends the whole form, with the booleans as strings', () => {
    const b = body(
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
