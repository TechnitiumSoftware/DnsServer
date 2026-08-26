import { describe, expect, it } from 'vitest'
import {
  construirCuerpoRegistro,
  formularioDesdeRegistro,
  formularioVacio,
  serializarSvcParams,
  TIPOS_REGISTRO,
  type ContextoRegistro,
  type FormularioRegistro,
} from './registro-form'
import type { Registro } from '../../api/registros'

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

function form(cambios: Partial<FormularioRegistro>): FormularioRegistro {
  return { ...formularioVacio(), ...cambios }
}

const ALTA: ContextoRegistro = { zone: 'casa.test', modo: 'add', updateSvcbHints: false }

function cuerpo(f: FormularioRegistro, ctx: ContextoRegistro = ALTA) {
  const r = construirCuerpoRegistro(f, ctx)
  if ('error' in r) throw new Error(`esperaba cuerpo, salió el aviso: ${r.error.text}`)
  return r.body
}

function error(f: FormularioRegistro, ctx: ContextoRegistro = ALTA) {
  const r = construirCuerpoRegistro(f, ctx)
  if ('body' in r) throw new Error('esperaba un aviso y salió un cuerpo')
  return r.error
}

describe('los 23 tipos del desplegable', () => {
  it('están en el orden de upstream', () => {
    expect(TIPOS_REGISTRO).toHaveLength(23)
    expect(TIPOS_REGISTRO[0]).toBe('A')
    expect(TIPOS_REGISTRO[2]).toBe('SOA')
    expect(TIPOS_REGISTRO[TIPOS_REGISTRO.length - 1]).toBe('Unknown')
  })
})

describe('alta — textos de aviso literales', () => {
  it('A sin dirección', () => {
    expect(error(form({ type: 'A', name: 'www' })).text).toBe(
      'Please enter an IP address to add the record.',
    )
  })

  it('CNAME en el ápice explica lo del ANAME', () => {
    expect(error(form({ type: 'CNAME', name: '@' })).text).toBe(
      "Please enter a name for the CNAME record since DNS protocol does not allow CNAME at zone's apex. If you need CNAME like function at the zone's apex then use ANAME record instead.",
    )
  })

  it('SRV pide un nombre con servicio y protocolo antes que nada', () => {
    const e = error(form({ type: 'SRV', name: '' }))
    expect(e.text).toBe('Please enter a name that includes service and protocol labels.')
    expect(e.campo).toBe('name')
  })

  it('el orden de validación de SRV es prioridad, peso, puerto y destino', () => {
    const base = { type: 'SRV', name: '_s._tcp' }
    expect(error(form(base)).campo).toBe('srvPriority')
    expect(error(form({ ...base, srvPriority: '1' })).campo).toBe('srvWeight')
    expect(error(form({ ...base, srvPriority: '1', srvWeight: '2' })).campo).toBe('srvPort')
    expect(error(form({ ...base, srvPriority: '1', srvWeight: '2', srvPort: '443' })).campo).toBe(
      'srvTarget',
    )
  })

  it('un tipo desconocido dice «to add record», sin artículo', () => {
    expect(error(form({ type: 'Unknown', unknownType: 'TYPE65280' })).text).toBe(
      'Please enter a hex value as the RDATA to add record.',
    )
  })

  it('la errata «resoure» de upstream se conserva', () => {
    expect(error(form({ type: 'Unknown' })).text).toBe(
      'Please enter a resoure record name or number to add record.',
    )
  })
})

describe('alta — valores que caen a un defecto en vez de dar error', () => {
  it('MX sin preferencia manda 1', () => {
    expect(cuerpo(form({ type: 'MX', name: 'x', mxExchange: 'mail.casa.test' })).preference).toBe('1')
  })

  it('CAA sin flags ni tag manda 0 e «issue»', () => {
    const b = cuerpo(form({ type: 'CAA', name: 'x', caaValue: 'letsencrypt.org' }))
    expect(b.flags).toBe('0')
    expect(b.tag).toBe('issue')
  })

  it('RP con los dos campos vacíos manda la raíz', () => {
    const b = cuerpo(form({ type: 'RP', name: 'x' }))
    expect(b.mailbox).toBe('.')
    expect(b.txtDomain).toBe('.')
  })
})

describe('alta — el cuerpo', () => {
  it('lleva zone, domain, type, ttl, overwrite, comments y expiryTtl', () => {
    const b = cuerpo(form({ type: 'A', name: 'www', valor: '10.0.0.1', ttl: '600', overwrite: true }))
    expect(b).toMatchObject({
      zone: 'casa.test',
      domain: 'www.casa.test',
      type: 'A',
      ttl: '600',
      overwrite: 'true',
      ipAddress: '10.0.0.1',
    })
    // El alta NO manda `disable` ni `newDomain`.
    expect(b).not.toHaveProperty('disable')
    expect(b).not.toHaveProperty('newDomain')
  })

  it('un nombre vacío es el ápice', () => {
    expect(cuerpo(form({ type: 'A', name: '', valor: '10.0.0.1' })).domain).toBe('casa.test')
  })

  it('TLSA con «Full» exige un PEM completo — sólo al dar de alta', () => {
    const f = form({
      type: 'TLSA',
      name: '_443._tcp',
      tlsaCertificateUsage: 'DANE-EE',
      tlsaSelector: 'Cert',
      tlsaMatchingType: 'Full',
      tlsaCertificateAssociationData: 'ABCD',
    })
    expect(error(f).text).toBe(
      'Please enter a complete certificate in PEM format as the Certificate Association Data to add the record.',
    )

    // Editando, ese mismo valor pasa.
    const original = reg('TLSA', {
      certificateUsage: 'DANE-EE',
      selector: 'Cert',
      matchingType: 'Full',
      certificateAssociationData: 'OLD',
    })
    const ctx: ContextoRegistro = { zone: 'casa.test', modo: 'update', original, updateSvcbHints: false }
    expect(cuerpo(f, ctx)).toMatchObject({ newTlsaCertificateAssociationData: 'ABCD' })
  })

  it('APP exige nombre y clase al dar de alta', () => {
    expect(error(form({ type: 'APP', name: 'x' })).text).toBe(
      'Please select an application name to add record.',
    )
  })
})

describe('edición — manda el valor viejo Y el nuevo', () => {
  const ctxDe = (original: Registro): ContextoRegistro => ({
    zone: 'casa.test',
    modo: 'update',
    original,
    updateSvcbHints: false,
  })

  it('A: ipAddress viejo y newIpAddress nuevo', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' })
    const b = cuerpo(form({ type: 'A', name: 'www', valor: '10.0.0.2' }), ctxDe(original))
    expect(b).toMatchObject({
      ipAddress: '10.0.0.1',
      newIpAddress: '10.0.0.2',
      domain: 'www.casa.test',
      newDomain: 'www.casa.test',
      disable: 'false',
    })
  })

  it('CNAME y DNAME NO mandan el viejo: sólo el valor nuevo', () => {
    const original = reg('CNAME', { cname: 'viejo.casa.test' })
    const b = cuerpo(form({ type: 'CNAME', name: 'ali', valor: 'nuevo.casa.test' }), ctxDe(original))
    expect(b.cname).toBe('nuevo.casa.test')
    expect(b).not.toHaveProperty('newCname')
  })

  it('TXT identifica por las cadenas en base64, no por el texto', () => {
    const original = reg('TXT', { text: 'viejo', characterStringsBase64: ['dmllam8='] })
    const b = cuerpo(form({ type: 'TXT', name: 'x', txt: 'nuevo' }), ctxDe(original))
    expect(b).toMatchObject({
      characterStringsBase64: 'dmllam8=',
      newText: 'nuevo',
      newSplitText: 'false',
    })
  })

  it('NAPTR: un reemplazo vacío cae a la raíz SÓLO al editar', () => {
    const original = reg('NAPTR', {
      order: 1, preference: 2, flags: 'U', services: 'x', regexp: 'y', replacement: '.',
    })
    const f = form({ type: 'NAPTR', name: 'x', naptrOrder: '1', naptrPreference: '2' })
    expect(cuerpo(f, ctxDe(original)).naptrNewReplacement).toBe('.')
    // Dando de alta, se manda vacío.
    expect(cuerpo(f).naptrReplacement).toBe('')
  })

  it('la edición reenvía el estado que tenía el registro, no lo cambia', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' }, { disabled: true })
    expect(cuerpo(form({ type: 'A', name: 'www', valor: '10.0.0.2' }), ctxDe(original)).disable).toBe(
      'true',
    )
  })

  it('APP editando no valida y toma el app y la clase del registro', () => {
    const original = reg('APP', { appName: 'Split Horizon', classPath: 'X.App', data: 'viejo' })
    const b = cuerpo(form({ type: 'APP', name: 'x', recordData: 'nuevo' }), ctxDe(original))
    expect(b).toMatchObject({ appName: 'Split Horizon', classPath: 'X.App', recordData: 'nuevo' })
  })

  it('FWD editando: sin «this-server» manda el proxy; con él, no', () => {
    const original = reg('FWD', {
      protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: false, proxyType: 'DefaultProxy',
    })
    const conProxy = cuerpo(form({ type: 'FWD', name: 'x', forwarder: '8.8.8.8' }), ctxDe(original))
    expect(conProxy).toHaveProperty('proxyType')

    const esteServidor = cuerpo(
      form({ type: 'FWD', name: 'x', forwarder: 'this-server' }),
      ctxDe(original),
    )
    expect(esteServidor).not.toHaveProperty('proxyType')
  })

  it('el aviso dice «to update the record»', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' })
    expect(error(form({ type: 'A', name: 'www' }), ctxDe(original)).text).toBe(
      'Please enter an IP address to update the record.',
    )
  })

  it('el aviso de un tipo desconocido SÍ lleva artículo al editar', () => {
    const original = reg('TYPE65280', { value: 'ABCD' })
    expect(error(form({ type: 'Unknown', unknownType: 'TYPE65280' }), ctxDe(original)).text).toBe(
      'Please enter a hex value as the RDATA to update the record.',
    )
  })
})

describe('SOA — sólo se edita, y valida siete campos en orden', () => {
  const original = reg('SOA', {})
  const ctx: ContextoRegistro = { zone: 'casa.test', modo: 'update', original, updateSvcbHints: false }

  it('el orden es primary, responsible, serial, refresh, retry, expire y minimum', () => {
    const campos = [
      'soaPrimaryNameServer',
      'soaResponsiblePerson',
      'soaSerial',
      'soaRefresh',
      'soaRetry',
      'soaExpire',
      'soaMinimum',
    ] as const

    const acumulado: Partial<FormularioRegistro> = { type: 'SOA', name: '@' }
    for (const campo of campos) {
      expect(error(form(acumulado), ctx).campo).toBe(campo)
      acumulado[campo] = 'x'
    }
  })
})

describe('parámetros de un SVCB', () => {
  it('se aplanan como clave|valor', () => {
    const r = serializarSvcParams([
      { clave: 'alpn', valor: 'h2' },
      { clave: 'port', valor: '443' },
    ])
    expect(r).toEqual({ valor: 'alpn|h2|port|443' })
  })

  it('una lista vacía viaja como la cadena «false»', () => {
    expect(serializarSvcParams([])).toEqual({ valor: 'false' })
  })

  it('una celda vacía es un aviso, no una fila que se ignora', () => {
    const r = serializarSvcParams([{ clave: 'alpn', valor: '' }])
    expect(r).toEqual({
      error: expect.objectContaining({
        text: 'Please enter a valid value in the text field in focus.',
      }),
    })
  })

  it('una barra vertical dentro de una celda también', () => {
    const r = serializarSvcParams([{ clave: 'alpn', valor: 'h2|h3' }])
    expect(r).toEqual({
      error: expect.objectContaining({
        text: "Please edit the value in the text field in focus to remove '|' character.",
      }),
    })
  })
})

describe('rellenar el formulario desde un registro', () => {
  it('el nombre se enseña relativo a la zona', () => {
    expect(formularioDesdeRegistro(reg('A', { ipAddress: '1.1.1.1' }), 'casa.test').name).toBe('www')
  })

  it('el ápice se enseña como @', () => {
    const r = reg('SOA', {}, { name: 'casa.test' })
    expect(formularioDesdeRegistro(r, 'casa.test').name).toBe('@')
  })

  it('un SVCB con target vacío se enseña como raíz', () => {
    const r = reg('SVCB', { svcPriority: 1, svcTargetName: '', svcParams: { alpn: 'h2' } })
    const f = formularioDesdeRegistro(r, 'casa.test')
    expect(f.svcbTargetName).toBe('.')
    expect(f.svcbParams).toEqual([{ clave: 'alpn', valor: 'h2' }])
  })

  it('el pegamento de un NS se enseña una dirección por línea', () => {
    const r = reg('NS', { nameServer: 'ns1' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] })
    expect(formularioDesdeRegistro(r, 'casa.test').nsGlue).toBe('10.0.0.1\n10.0.0.2')
  })
})
