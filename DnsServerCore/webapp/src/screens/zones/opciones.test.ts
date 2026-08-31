import { describe, expect, it } from 'vitest'
import type { OpcionesZona } from '../../api/zones'
import {
  aclEditable,
  construirCuerpoOpciones,
  estadoOpciones,
  formularioDesdeOpciones,
  notificacionConLista,
} from './opciones'

function options(cambios: Partial<OpcionesZona> = {}): OpcionesZona {
  return {
    name: 'casa.test',
    type: 'Primary',
    dnssecStatus: 'Unsigned',
    disabled: false,
    catalog: null,
    queryAccess: 'Allow',
    queryAccessNetworkACL: [],
    zoneTransfer: 'AllowOnlyZoneNameServers',
    zoneTransferNetworkACL: [],
    zoneTransferTsigKeyNames: [],
    notify: 'ZoneNameServers',
    notifyNameServers: [],
    update: 'Deny',
    updateNetworkACL: [],
    updateSecurityPolicies: [],
    availableCatalogZoneNames: [],
    availableTsigKeyNames: [],
    ...cambios,
  }
}

describe('which tabs are visible', () => {
  it('a standalone Primary with no catalogs available does not show \"General\"', () => {
    const e = estadoOpciones(options())
    expect(e.pestanas).toEqual(['Query Access', 'Zone Transfer', 'Notify', 'Dynamic Updates'])
    expect(e.pestanaInicial).toBe('Query Access')
  })

  it('with catalogs available \"General\" appears and is the one that comes up open', () => {
    const e = estadoOpciones(options({ availableCatalogZoneNames: ['cat.test'] }))
    expect(e.pestanas[0]).toBe('General')
    expect(e.pestanaInicial).toBe('General')
  })

  it('a Catalog opens on \"Query Access\" even when there are more tabs', () => {
    const e = estadoOpciones(options({ type: 'Catalog' }))
    expect(e.pestanaInicial).toBe('Query Access')
    // A Catalog has no dynamic updates.
    expect(e.pestanas).not.toContain('Dynamic Updates')
  })

  it('the secondaries and the stub always open on \"General\"', () => {
    for (const type of ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']) {
      expect(estadoOpciones(options({ type })).pestanaInicial).toBe('General')
    }
  })

  it('a Stub has neither transfer nor notify', () => {
    const e = estadoOpciones(options({ type: 'Stub' }))
    expect(e.pestanas).not.toContain('Zone Transfer')
    expect(e.pestanas).not.toContain('Notify')
  })

  it('a catalog zone that does NOT allow overriding hides the whole tab', () => {
    const e = estadoOpciones(
      options({ catalog: 'cat.test', overrideCatalogQueryAccess: false, overrideCatalogZoneTransfer: false, overrideCatalogNotify: false }),
    )
    expect(e.pestanas).not.toContain('Query Access')
    expect(e.pestanas).not.toContain('Zone Transfer')
    expect(e.pestanas).not.toContain('Notify')
  })

  it('if it does allow it, the tab comes back and is editable', () => {
    const e = estadoOpciones(options({ catalog: 'cat.test', overrideCatalogQueryAccess: true }))
    expect(e.pestanas).toContain('Query Access')
    expect(e.queryAccessBloqueado).toBe(false)
  })

  it('a SecondaryCatalog shows Query Access and Zone Transfer, but LOCKED', () => {
    const e = estadoOpciones(options({ type: 'SecondaryCatalog' }))
    expect(e.queryAccessBloqueado).toBe(true)
    expect(e.zoneTransferBloqueado).toBe(true)
  })

  it('a Secondary that is a member of a secondary catalog cannot touch its primary', () => {
    const e = estadoOpciones(
      options({ type: 'Secondary', catalog: 'cat.test', isSecondaryCatalogMember: true, overrideCatalogPrimaryNameServers: true }),
    )
    expect(e.servidorPrimarioBloqueado).toBe(true)
    expect(e.catalogoFijo).toBe(true)
  })
})

describe('which criteria are offered', () => {
  it('the \"Name Servers In Zone\" ones disappear on five types', () => {
    for (const type of ['Stub', 'Forwarder', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog']) {
      expect(estadoOpciones(options({ type })).queryAccessConNameServers).toBe(false)
    }
    expect(estadoOpciones(options({ type: 'Primary' })).queryAccessConNameServers).toBe(true)
  })

  it('the update policies only exist on Primary and Forwarder', () => {
    expect(estadoOpciones(options({ type: 'Primary' })).securityPolicies).toBe(true)
    expect(estadoOpciones(options({ type: 'Secondary' })).securityPolicies).toBe(false)
  })

  it('the separate catalog notify only exists on a Catalog', () => {
    expect(estadoOpciones(options({ type: 'Catalog' })).notifySeparados).toBe(true)
    expect(estadoOpciones(options({ type: 'Primary' })).notifySeparados).toBe(false)
  })
})

describe('the lists are enabled by some criteria and not by others', () => {
  it('the ACL only with the two \"UseSpecifiedNetworkACL\"', () => {
    expect(aclEditable('UseSpecifiedNetworkACL')).toBe(true)
    expect(aclEditable('AllowZoneNameServersAndUseSpecifiedNetworkACL')).toBe(true)
    expect(aclEditable('Allow')).toBe(false)
    expect(aclEditable('Deny')).toBe(false)
  })

  it('the notify list with three of the five criteria', () => {
    expect(notificacionConLista('SpecifiedNameServers')).toBe(true)
    expect(notificacionConLista('BothZoneAndSpecifiedNameServers')).toBe(true)
    expect(notificacionConLista('SeparateNameServersForCatalogAndMemberZones')).toBe(true)
    expect(notificacionConLista('ZoneNameServers')).toBe(false)
    expect(notificacionConLista('None')).toBe(false)
  })
})

describe('the body of options/set', () => {
  const f = () => formularioDesdeOpciones(options())

  it('the empty lists do NOT all travel the same', () => {
    const r = construirCuerpoOpciones(f(), 'Primary')
    if ('error' in r) throw new Error('esperaba cuerpo')

    // Four fall to the string "false"…
    expect(r.body.zoneTransferNetworkACL).toBe('false')
    expect(r.body.zoneTransferTsigKeyNames).toBe('false')
    expect(r.body.notifyNameServers).toBe('false')
    expect(r.body.updateNetworkACL).toBe('false')
    expect(r.body.updateSecurityPolicies).toBe('false')
    // …and two travel empty as they are.
    expect(r.body.primaryNameServerAddresses).toBe('')
    expect(r.body.queryAccessNetworkACL).toBe('')
  })

  it('the lists with content are cleaned and go comma-separated', () => {
    const form = { ...f(), notifyNameServers: '10.0.0.1\n\n10.0.0.2\n' }
    const r = construirCuerpoOpciones(form, 'Primary')
    if ('error' in r) throw new Error('esperaba cuerpo')
    expect(r.body.notifyNameServers).toBe('10.0.0.1,10.0.0.2')
  })

  it('a SecondaryForwarder with no primary servers gives an alert', () => {
    const r = construirCuerpoOpciones(f(), 'SecondaryForwarder')
    if ('body' in r) throw new Error('esperaba aviso')
    expect(r.error.text).toBe('Please enter at least one primary name server address to proceed.')
    expect(r.error.tab).toBe('General')
  })

  it('the policies serialise as tsig|domain|types', () => {
    const form = {
      ...f(),
      updateSecurityPolicies: [
        { tsigKeyName: 'k1', domain: 'casa.test', allowedTypes: 'A, AAAA' },
        { tsigKeyName: 'k2', domain: 'sub.casa.test', allowedTypes: 'TXT' },
      ],
    }
    const r = construirCuerpoOpciones(form, 'Primary')
    if ('error' in r) throw new Error('esperaba cuerpo')
    expect(r.body.updateSecurityPolicies).toBe('k1|casa.test|A, AAAA|k2|sub.casa.test|TXT')
  })

  it('a policy with a gap gives the required-field alert', () => {
    const form = {
      ...f(),
      updateSecurityPolicies: [{ tsigKeyName: '', domain: 'casa.test', allowedTypes: 'A' }],
    }
    const r = construirCuerpoOpciones(form, 'Primary')
    if ('body' in r) throw new Error('esperaba aviso')
    expect(r.error.text).toBe('Please enter a valid value in the text field in focus.')
    expect(r.error.tab).toBe('Dynamic Updates')
  })
})

describe('filling the form', () => {
  it('an unknown transfer protocol falls to TCP', () => {
    expect(
      formularioDesdeOpciones(options({ primaryZoneTransferProtocol: 'Loquesea' })).primaryZoneTransferProtocol,
    ).toBe('Tcp')
    expect(
      formularioDesdeOpciones(options({ primaryZoneTransferProtocol: 'Quic' })).primaryZoneTransferProtocol,
    ).toBe('Quic')
  })

  it('the override checkboxes are false if the zone is not in a catalog', () => {
    const f = formularioDesdeOpciones(options({ overrideCatalogQueryAccess: true, catalog: null }))
    expect(f.overrideCatalogQueryAccess).toBe(false)
  })

  it('the lists are shown one per line', () => {
    const f = formularioDesdeOpciones(options({ queryAccessNetworkACL: ['10.0.0.0/8', '192.168.0.0/16'] }))
    expect(f.queryAccessNetworkACL).toBe('10.0.0.0/8\n192.168.0.0/16')
  })
})
