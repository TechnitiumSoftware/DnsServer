import { describe, expect, it } from 'vitest'
import type { OpcionesZona } from '../../api/zones'
import {
  aclEditable,
  construirCuerpoOpciones,
  estadoOpciones,
  formularioDesdeOpciones,
  notificacionConLista,
} from './opciones'

function opciones(cambios: Partial<OpcionesZona> = {}): OpcionesZona {
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

describe('qué pestañas se ven', () => {
  it('una Primary suelta sin catálogos disponibles no enseña «General»', () => {
    const e = estadoOpciones(opciones())
    expect(e.pestanas).toEqual(['Query Access', 'Zone Transfer', 'Notify', 'Dynamic Updates'])
    expect(e.pestanaInicial).toBe('Query Access')
  })

  it('con catálogos disponibles aparece «General» y es la que sale abierta', () => {
    const e = estadoOpciones(opciones({ availableCatalogZoneNames: ['cat.test'] }))
    expect(e.pestanas[0]).toBe('General')
    expect(e.pestanaInicial).toBe('General')
  })

  it('una Catalog abre «Query Access» aunque haya más pestañas', () => {
    const e = estadoOpciones(opciones({ type: 'Catalog' }))
    expect(e.pestanaInicial).toBe('Query Access')
    // Una Catalog no tiene actualizaciones dinámicas.
    expect(e.pestanas).not.toContain('Dynamic Updates')
  })

  it('las secundarias y la stub abren siempre «General»', () => {
    for (const type of ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']) {
      expect(estadoOpciones(opciones({ type })).pestanaInicial).toBe('General')
    }
  })

  it('un Stub no tiene transferencia ni notificación', () => {
    const e = estadoOpciones(opciones({ type: 'Stub' }))
    expect(e.pestanas).not.toContain('Zone Transfer')
    expect(e.pestanas).not.toContain('Notify')
  })

  it('una zona de catálogo que NO deja sobrescribir esconde la pestaña entera', () => {
    const e = estadoOpciones(
      opciones({ catalog: 'cat.test', overrideCatalogQueryAccess: false, overrideCatalogZoneTransfer: false, overrideCatalogNotify: false }),
    )
    expect(e.pestanas).not.toContain('Query Access')
    expect(e.pestanas).not.toContain('Zone Transfer')
    expect(e.pestanas).not.toContain('Notify')
  })

  it('si la deja, la pestaña vuelve y es editable', () => {
    const e = estadoOpciones(opciones({ catalog: 'cat.test', overrideCatalogQueryAccess: true }))
    expect(e.pestanas).toContain('Query Access')
    expect(e.queryAccessBloqueado).toBe(false)
  })

  it('una SecondaryCatalog enseña Query Access y Zone Transfer, pero BLOQUEADAS', () => {
    const e = estadoOpciones(opciones({ type: 'SecondaryCatalog' }))
    expect(e.queryAccessBloqueado).toBe(true)
    expect(e.zoneTransferBloqueado).toBe(true)
  })

  it('una Secondary miembro de un catálogo secundario no puede tocar su primario', () => {
    const e = estadoOpciones(
      opciones({ type: 'Secondary', catalog: 'cat.test', isSecondaryCatalogMember: true, overrideCatalogPrimaryNameServers: true }),
    )
    expect(e.servidorPrimarioBloqueado).toBe(true)
    expect(e.catalogoFijo).toBe(true)
  })
})

describe('qué criterios se ofrecen', () => {
  it('los de «Name Servers In Zone» desaparecen en cinco tipos', () => {
    for (const type of ['Stub', 'Forwarder', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog']) {
      expect(estadoOpciones(opciones({ type })).queryAccessConNameServers).toBe(false)
    }
    expect(estadoOpciones(opciones({ type: 'Primary' })).queryAccessConNameServers).toBe(true)
  })

  it('las políticas de actualización sólo existen en Primary y Forwarder', () => {
    expect(estadoOpciones(opciones({ type: 'Primary' })).politicasDeSeguridad).toBe(true)
    expect(estadoOpciones(opciones({ type: 'Secondary' })).politicasDeSeguridad).toBe(false)
  })

  it('la notificación separada de catálogos sólo existe en una Catalog', () => {
    expect(estadoOpciones(opciones({ type: 'Catalog' })).notifySeparados).toBe(true)
    expect(estadoOpciones(opciones({ type: 'Primary' })).notifySeparados).toBe(false)
  })
})

describe('las listas se habilitan con unos criterios y no con otros', () => {
  it('la ACL sólo con los dos «UseSpecifiedNetworkACL»', () => {
    expect(aclEditable('UseSpecifiedNetworkACL')).toBe(true)
    expect(aclEditable('AllowZoneNameServersAndUseSpecifiedNetworkACL')).toBe(true)
    expect(aclEditable('Allow')).toBe(false)
    expect(aclEditable('Deny')).toBe(false)
  })

  it('la lista de notificación con tres de los cinco criterios', () => {
    expect(notificacionConLista('SpecifiedNameServers')).toBe(true)
    expect(notificacionConLista('BothZoneAndSpecifiedNameServers')).toBe(true)
    expect(notificacionConLista('SeparateNameServersForCatalogAndMemberZones')).toBe(true)
    expect(notificacionConLista('ZoneNameServers')).toBe(false)
    expect(notificacionConLista('None')).toBe(false)
  })
})

describe('el cuerpo de options/set', () => {
  const f = () => formularioDesdeOpciones(opciones())

  it('las listas vacías NO viajan todas igual', () => {
    const r = construirCuerpoOpciones(f(), 'Primary')
    if ('error' in r) throw new Error('esperaba cuerpo')

    // Cuatro caen a la cadena «false»…
    expect(r.body.zoneTransferNetworkACL).toBe('false')
    expect(r.body.zoneTransferTsigKeyNames).toBe('false')
    expect(r.body.notifyNameServers).toBe('false')
    expect(r.body.updateNetworkACL).toBe('false')
    expect(r.body.updateSecurityPolicies).toBe('false')
    // …y dos viajan vacías tal cual.
    expect(r.body.primaryNameServerAddresses).toBe('')
    expect(r.body.queryAccessNetworkACL).toBe('')
  })

  it('las listas con contenido se limpian y van separadas por coma', () => {
    const form = { ...f(), notifyNameServers: '10.0.0.1\n\n10.0.0.2\n' }
    const r = construirCuerpoOpciones(form, 'Primary')
    if ('error' in r) throw new Error('esperaba cuerpo')
    expect(r.body.notifyNameServers).toBe('10.0.0.1,10.0.0.2')
  })

  it('una SecondaryForwarder sin servidores primarios da aviso', () => {
    const r = construirCuerpoOpciones(f(), 'SecondaryForwarder')
    if ('body' in r) throw new Error('esperaba aviso')
    expect(r.error.text).toBe('Please enter at least one primary name server address to proceed.')
    expect(r.error.tab).toBe('General')
  })

  it('las políticas se serializan como tsig|dominio|tipos', () => {
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

  it('una política con un hueco da el aviso de campo obligatorio', () => {
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

describe('rellenar el formulario', () => {
  it('un protocolo de transferencia desconocido cae a TCP', () => {
    expect(
      formularioDesdeOpciones(opciones({ primaryZoneTransferProtocol: 'Loquesea' })).primaryZoneTransferProtocol,
    ).toBe('Tcp')
    expect(
      formularioDesdeOpciones(opciones({ primaryZoneTransferProtocol: 'Quic' })).primaryZoneTransferProtocol,
    ).toBe('Quic')
  })

  it('las casillas de sobrescritura son falsas si la zona no está en un catálogo', () => {
    const f = formularioDesdeOpciones(opciones({ overrideCatalogQueryAccess: true, catalog: null }))
    expect(f.overrideCatalogQueryAccess).toBe(false)
  })

  it('las listas se enseñan una por línea', () => {
    const f = formularioDesdeOpciones(opciones({ queryAccessNetworkACL: ['10.0.0.0/8', '192.168.0.0/16'] }))
    expect(f.queryAccessNetworkACL).toBe('10.0.0.0/8\n192.168.0.0/16')
  })
})
