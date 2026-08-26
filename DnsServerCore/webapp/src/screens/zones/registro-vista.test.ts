import { describe, expect, it } from 'vitest'
import type { Registro } from '../../api/registros'
import {
  accionesDeFila,
  celdasDeRegistro,
  escaparTxt,
  nombreRelativo,
  ocultarDnssec,
  pieDeRegistro,
} from './registro-vista'
import { cabeceraDeZona, tiposOcultosAlAnadir } from './vista-zona'

function reg(type: string, rData: Record<string, unknown>, extra: Partial<Registro> = {}): Registro {
  return {
    name: 'www.casa.test',
    type,
    ttl: 3600,
    ttlString: '1h',
    disabled: false,
    rData,
    dnssecStatus: 'Unknown',
    lastUsedOn: '0001-01-01T00:00:00',
    lastModified: '2026-08-26T10:00:00Z',
    expiryTtl: 0,
    expiryTtlString: '',
    ...extra,
  }
}

/** Aplana las celdas a pares para poder afirmar sobre ellas sin montar nada. */
function pares(r: Registro): Record<string, string> {
  const out: Record<string, string> = {}
  for (const c of celdasDeRegistro(r)) {
    if (c.clase === 'pares') for (const p of c.pares) out[p.etiqueta] = p.valor
  }
  return out
}

describe('la celda Data por tipo', () => {
  it('A y AAAA son sólo la dirección', () => {
    expect(celdasDeRegistro(reg('A', { ipAddress: '10.0.0.1' }))).toEqual([
      { clase: 'valor', texto: '10.0.0.1' },
    ])
  })

  it('SOA compone valor y cadena legible en cuatro campos', () => {
    const p = pares(
      reg('SOA', {
        primaryNameServer: 'ns1',
        responsiblePerson: 'a@b',
        serial: 7,
        refresh: 900, refreshString: '15m',
        retry: 300, retryString: '5m',
        expire: 604800, expireString: '1w',
        minimum: 900, minimumString: '15m',
        useSerialDateScheme: false,
      }),
    )
    expect(p['Refresh:']).toBe('900 (15m)')
    expect(p['Expire:']).toBe('604800 (1w)')
    expect(p['Use Serial Date Scheme:']).toBe('false')
  })

  it('DS y RRSIG componen «algoritmo (número)»', () => {
    const p = pares(reg('DS', { keyTag: 1, algorithm: 'ECDSAP256SHA256', algorithmNumber: 13, digestType: 'SHA256', digestTypeNumber: '2', digest: 'AB' }))
    expect(p['Algorithm:']).toBe('ECDSAP256SHA256 (13)')
    expect(p['Digest Type:']).toBe('SHA256 (2)')
  })

  it('NS enseña el pegamento sólo si lo trae', () => {
    expect(pares(reg('NS', { nameServer: 'ns1' }))).not.toHaveProperty('Glue Addresses:')
    const conGlue = pares(reg('NS', { nameServer: 'ns1' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] }))
    expect(conGlue['Glue Addresses:']).toBe('10.0.0.1, 10.0.0.2')
  })

  it('un TXT partido enseña cada cadena entre comillas y en su línea', () => {
    const celdas = celdasDeRegistro(
      reg('TXT', { splitText: true, characterStrings: ['uno', 'dos'], text: 'uno dos' }),
    )
    expect(celdas[0]).toEqual({ clase: 'lineas', lineas: ['"uno"', '"dos"'] })
  })

  it('escapa barras, retornos, saltos y comillas de un TXT', () => {
    expect(escaparTxt('a\\b"c\nd')).toBe('a\\\\b\\"c\\nd')
  })

  it('SVCB dice el modo según la prioridad', () => {
    expect(pares(reg('SVCB', { svcPriority: 0, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '0 (alias mode)',
    )
    expect(pares(reg('SVCB', { svcPriority: 1, svcTargetName: 'x', svcParams: {} }))['Priority:']).toBe(
      '1 (service mode)',
    )
  })

  it('SVCB esconde las pistas cuyo valor pone el servidor', () => {
    const celdas = celdasDeRegistro(
      reg('SVCB', {
        svcPriority: 1,
        svcTargetName: 'x',
        svcParams: { alpn: 'h2', ipv4hint: '10.0.0.1', ipv6hint: '::1' },
        autoIpv4Hint: true,
        autoIpv6Hint: false,
      }),
    )
    const tabla = celdas.find((c) => c.clase === 'tabla')
    expect(tabla).toBeDefined()
    const claves = tabla!.clase === 'tabla' ? tabla!.filas.map((f) => f[0]) : []
    expect(claves).toEqual(['alpn', 'ipv6hint'])
  })

  it('un DNSKEY sin estado no enseña la fila «Key State»', () => {
    expect(pares(reg('DNSKEY', { flags: 257, protocol: 3, algorithm: 'X', algorithmNumber: 13, publicKey: 'AA', computedKeyTag: 1 }))).not.toHaveProperty(
      'Key State:',
    )
  })

  it('FWD sólo enseña el proxy cuando el tipo lo tiene', () => {
    const sin = pares(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'DefaultProxy' }))
    expect(sin).not.toHaveProperty('Proxy Address:')
    const con = pares(reg('FWD', { protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: true, proxyType: 'Socks5', proxyAddress: '10.0.0.9', proxyPort: 1080 }))
    expect(con['Proxy Address:']).toBe('10.0.0.9')
  })

  it('un tipo desconocido enseña su RDATA', () => {
    expect(pares(reg('TYPE65280', { value: 'ABCD' }))['RDATA:']).toBe('ABCD')
  })
})

describe('el pie de la celda', () => {
  const AHORA = Date.parse('2026-08-26T10:04:00Z')

  it('«nunca» no lleva antigüedad detrás', () => {
    const p = pieDeRegistro(reg('A', {}), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Used:')?.valor).toContain('(never)')
  })

  it('la última modificación sí la lleva', () => {
    const p = pieDeRegistro(reg('A', {}), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Modified:')?.valor).toContain('4 minutes ago')
  })

  it('una fecha de modificación mínima NO se enseña', () => {
    const p = pieDeRegistro(reg('A', {}, { lastModified: '0001-01-01T00:00:00' }), AHORA)
    expect(p.find((x) => x.etiqueta === 'Last Modified:')).toBeUndefined()
  })

  it('la expiración sólo aparece con expiryTtl > 0', () => {
    expect(pieDeRegistro(reg('A', {}), AHORA).find((x) => x.etiqueta === 'Expiry TTL:')).toBeUndefined()
    const con = pieDeRegistro(reg('A', {}, { expiryTtl: 3600, expiryTtlString: '1h' }), AHORA)
    expect(con.find((x) => x.etiqueta === 'Expiry TTL:')?.valor).toBe('3600 (1h)')
  })
})

describe('el nombre relativo a la zona', () => {
  it('el ápice es @', () => {
    expect(nombreRelativo('casa.test', 'casa.test')).toBe('@')
  })
  it('un sub-dominio pierde el sufijo', () => {
    expect(nombreRelativo('www.casa.test', 'casa.test')).toBe('www')
    expect(nombreRelativo('a.b.casa.test', 'casa.test')).toBe('a.b')
  })
  it('el nombre vacío es la raíz', () => {
    expect(nombreRelativo('', '.')).toBe('@')
  })
})

describe('qué botones ofrece una fila', () => {
  it('en una secundaria no hay ninguno', () => {
    for (const t of ['Secondary', 'SecondaryForwarder', 'SecondaryCatalog', 'Stub']) {
      expect(accionesDeFila(t, 'A').ocultas).toBe(true)
    }
  })

  it('en una Catalog sólo el SOA se puede editar; el resto no ofrece nada', () => {
    expect(accionesDeFila('Catalog', 'SOA')).toEqual({ ocultas: false, soloEdicion: true })
    expect(accionesDeFila('Catalog', 'A').ocultas).toBe(true)
  })

  it('en una Primary el SOA se edita pero no se borra ni se deshabilita', () => {
    expect(accionesDeFila('Primary', 'SOA')).toEqual({ ocultas: false, soloEdicion: true })
  })

  it('los seis registros que genera DNSSEC no ofrecen botones', () => {
    for (const t of ['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'ZONEMD']) {
      expect(accionesDeFila('Primary', t).ocultas).toBe(true)
    }
  })

  it('un registro normal los ofrece todos', () => {
    expect(accionesDeFila('Primary', 'A')).toEqual({ ocultas: false, soloEdicion: false })
  })
})

describe('esconder los registros DNSSEC', () => {
  it('quita los cinco tipos, no seis', () => {
    const lista = ['A', 'RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM', 'ZONEMD'].map((t) =>
      reg(t, {}),
    )
    // ZONEMD no está en la lista de `zoneHideDnssecRecords` aunque sí en la de
    // registros sin acciones. Son dos listas distintas de upstream.
    expect(ocultarDnssec(lista).map((r) => r.type)).toEqual(['A', 'ZONEMD'])
  })
})

describe('la cabecera de una zona abierta', () => {
  it('una Primary sin firmar ofrece firmar y nada más de DNSSEC', () => {
    const c = cabeceraDeZona('Primary', 'Unsigned')
    expect(c.dnssec).toBe(true)
    expect(c.firmar).toBe(true)
    expect(c.desfirmar).toBe(false)
    expect(c.verDs).toBe(false)
  })

  it('una Primary firmada ofrece todo menos firmar', () => {
    const c = cabeceraDeZona('Primary', 'SignedWithNSEC')
    expect(c.firmar).toBe(false)
    expect(c.desfirmar).toBe(true)
    expect(c.verDs).toBe(true)
    expect(c.propiedades).toBe(true)
  })

  it('una Secondary firmada enseña el menú pero SÓLO para ocultar registros', () => {
    const c = cabeceraDeZona('Secondary', 'SignedWithNSEC3')
    expect(c.dnssec).toBe(true)
    expect(c.alternarRegistrosDnssec).toBe(true)
    expect(c.firmar).toBe(false)
    expect(c.verDs).toBe(false)
    expect(c.propiedades).toBe(false)
  })

  it('una Secondary sin firmar no enseña el menú DNSSEC', () => {
    expect(cabeceraDeZona('Secondary', 'Unsigned').dnssec).toBe(false)
  })

  it('sólo Primary y Forwarder dejan añadir registros a mano', () => {
    expect(cabeceraDeZona('Primary', 'Unsigned').anadirRegistro).toBe(true)
    expect(cabeceraDeZona('Forwarder', 'Unsigned').anadirRegistro).toBe(true)
    expect(cabeceraDeZona('Secondary', 'Unsigned').anadirRegistro).toBe(false)
    expect(cabeceraDeZona('Catalog', 'Unsigned').anadirRegistro).toBe(false)
  })

  it('exportar cubre más tipos que importar', () => {
    expect(cabeceraDeZona('Secondary', 'Unsigned').exportar).toBe(true)
    expect(cabeceraDeZona('Secondary', 'Unsigned').importar).toBe(false)
  })
})

describe('qué tipos ofrece «Add Record»', () => {
  it('una Forwarder esconde los tres de DNSSEC', () => {
    expect(tiposOcultosAlAnadir('Forwarder', 'Unsigned')).toEqual(['DS', 'SSHFP', 'TLSA'])
  })

  it('una Primary sin firmar esconde FWD y los tres de DNSSEC', () => {
    expect(tiposOcultosAlAnadir('Primary', 'Unsigned')).toEqual(['FWD', 'DS', 'SSHFP', 'TLSA'])
  })

  it('una Primary FIRMADA cambia qué esconde: aparecen DS/SSHFP/TLSA y se van ANAME y APP', () => {
    expect(tiposOcultosAlAnadir('Primary', 'SignedWithNSEC')).toEqual(['FWD', 'ANAME', 'APP'])
  })
})
