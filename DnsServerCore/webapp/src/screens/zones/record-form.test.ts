import { describe, expect, it } from 'vitest'
import {
  buildRecordBody,
  formFromRecord,
  emptyForm,
  serializeSvcParams,
  RECORD_TYPES,
  type RecordContext,
  type RecordForm,
} from './record-form'
import type { ResourceRecord } from '../../api/records'

function reg(type: string, rData: Record<string, unknown>, extra: Partial<ResourceRecord> = {}): ResourceRecord {
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

function form(cambios: Partial<RecordForm>): RecordForm {
  return { ...emptyForm(), ...cambios }
}

const ADD: RecordContext = { zone: 'casa.test', mode: 'add', updateSvcbHints: false }

function body(f: RecordForm, ctx: RecordContext = ADD) {
  const r = buildRecordBody(f, ctx)
  if ('error' in r) throw new Error(`esperaba cuerpo, salió el aviso: ${r.error.text}`)
  return r.body
}

function error(f: RecordForm, ctx: RecordContext = ADD) {
  const r = buildRecordBody(f, ctx)
  if ('body' in r) throw new Error('esperaba un aviso y salió un cuerpo')
  return r.error
}

describe('the 23 types of the dropdown', () => {
  it('they are in the order of upstream', () => {
    expect(RECORD_TYPES).toHaveLength(23)
    expect(RECORD_TYPES[0]).toBe('A')
    expect(RECORD_TYPES[2]).toBe('SOA')
    expect(RECORD_TYPES[RECORD_TYPES.length - 1]).toBe('Unknown')
  })
})

describe('add — literal alert texts', () => {
  it('A with no address', () => {
    expect(error(form({ type: 'A', name: 'www' })).text).toBe(
      'Please enter an IP address to add the record.',
    )
  })

  it('CNAME at the apex explains the ANAME business', () => {
    expect(error(form({ type: 'CNAME', name: '@' })).text).toBe(
      "Please enter a name for the CNAME record since DNS protocol does not allow CNAME at zone's apex. If you need CNAME like function at the zone's apex then use ANAME record instead.",
    )
  })

  it('SRV asks for a name with service and protocol before anything else', () => {
    const e = error(form({ type: 'SRV', name: '' }))
    expect(e.text).toBe('Please enter a name that includes service and protocol labels.')
    expect(e.field).toBe('name')
  })

  it('the validation order of SRV is priority, weight, port and target', () => {
    const base = { type: 'SRV', name: '_s._tcp' }
    expect(error(form(base)).field).toBe('srvPriority')
    expect(error(form({ ...base, srvPriority: '1' })).field).toBe('srvWeight')
    expect(error(form({ ...base, srvPriority: '1', srvWeight: '2' })).field).toBe('srvPort')
    expect(error(form({ ...base, srvPriority: '1', srvWeight: '2', srvPort: '443' })).field).toBe(
      'srvTarget',
    )
  })

  it('an unknown type says \"to add record\", with no article', () => {
    expect(error(form({ type: 'Unknown', unknownType: 'TYPE65280' })).text).toBe(
      'Please enter a hex value as the RDATA to add record.',
    )
  })

  it('the \"resoure\" typo of upstream is kept', () => {
    expect(error(form({ type: 'Unknown' })).text).toBe(
      'Please enter a resoure record name or number to add record.',
    )
  })
})

describe('add — values that fall to a default instead of erroring', () => {
  it('MX with no preference sends 1', () => {
    expect(body(form({ type: 'MX', name: 'x', mxExchange: 'mail.casa.test' })).preference).toBe('1')
  })

  it('CAA with no flags and no tag sends 0 and \"issue\"', () => {
    const b = body(form({ type: 'CAA', name: 'x', caaValue: 'letsencrypt.org' }))
    expect(b.flags).toBe('0')
    expect(b.tag).toBe('issue')
  })

  it('RP with both fields empty sends the root', () => {
    const b = body(form({ type: 'RP', name: 'x' }))
    expect(b.mailbox).toBe('.')
    expect(b.txtDomain).toBe('.')
  })
})

describe('add — the body', () => {
  it('carries zone, domain, type, ttl, overwrite, comments and expiryTtl', () => {
    const b = body(form({ type: 'A', name: 'www', value: '10.0.0.1', ttl: '600', overwrite: true }))
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

  it('an empty name is the apex', () => {
    expect(body(form({ type: 'A', name: '', value: '10.0.0.1' })).domain).toBe('casa.test')
  })

  it('TLSA with \"Full\" requires a complete PEM — only when adding', () => {
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
    const ctx: RecordContext = { zone: 'casa.test', mode: 'update', original, updateSvcbHints: false }
    expect(body(f, ctx)).toMatchObject({ newTlsaCertificateAssociationData: 'ABCD' })
  })

  it('APP requires name and class when adding', () => {
    expect(error(form({ type: 'APP', name: 'x' })).text).toBe(
      'Please select an application name to add record.',
    )
  })
})

describe('edit — sends the old value AND the new one', () => {
  const ctxDe = (original: ResourceRecord): RecordContext => ({
    zone: 'casa.test',
    mode: 'update',
    original,
    updateSvcbHints: false,
  })

  it('A: old ipAddress and new newIpAddress', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' })
    const b = body(form({ type: 'A', name: 'www', value: '10.0.0.2' }), ctxDe(original))
    expect(b).toMatchObject({
      ipAddress: '10.0.0.1',
      newIpAddress: '10.0.0.2',
      domain: 'www.casa.test',
      newDomain: 'www.casa.test',
      disable: 'false',
    })
  })

  it('CNAME and DNAME do NOT send the old one: only the new value', () => {
    const original = reg('CNAME', { cname: 'viejo.casa.test' })
    const b = body(form({ type: 'CNAME', name: 'ali', value: 'nuevo.casa.test' }), ctxDe(original))
    expect(b.cname).toBe('nuevo.casa.test')
    expect(b).not.toHaveProperty('newCname')
  })

  it('TXT identifies by the base64 strings, not by the text', () => {
    const original = reg('TXT', { text: 'viejo', characterStringsBase64: ['dmllam8='] })
    const b = body(form({ type: 'TXT', name: 'x', txt: 'nuevo' }), ctxDe(original))
    expect(b).toMatchObject({
      characterStringsBase64: 'dmllam8=',
      newText: 'nuevo',
      newSplitText: 'false',
    })
  })

  it('NAPTR: an empty replacement falls to the root ONLY when editing', () => {
    const original = reg('NAPTR', {
      order: 1, preference: 2, flags: 'U', services: 'x', regexp: 'y', replacement: '.',
    })
    const f = form({ type: 'NAPTR', name: 'x', naptrOrder: '1', naptrPreference: '2' })
    expect(body(f, ctxDe(original)).naptrNewReplacement).toBe('.')
    // When adding, it is sent empty.
    expect(body(f).naptrReplacement).toBe('')
  })

  it('the edit resends the state the record had, it does not change it', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' }, { disabled: true })
    expect(body(form({ type: 'A', name: 'www', value: '10.0.0.2' }), ctxDe(original)).disable).toBe(
      'true',
    )
  })

  it('APP when editing does not validate and takes the app and class from the record', () => {
    const original = reg('APP', { appName: 'Split Horizon', classPath: 'X.App', data: 'viejo' })
    const b = body(form({ type: 'APP', name: 'x', recordData: 'nuevo' }), ctxDe(original))
    expect(b).toMatchObject({ appName: 'Split Horizon', classPath: 'X.App', recordData: 'nuevo' })
  })

  it('FWD when editing: without \"this-server\" it sends the proxy; with it, no', () => {
    const original = reg('FWD', {
      protocol: 'Udp', forwarder: '1.1.1.1', priority: 1, dnssecValidation: false, proxyType: 'DefaultProxy',
    })
    const withProxy = body(form({ type: 'FWD', name: 'x', forwarder: '8.8.8.8' }), ctxDe(original))
    expect(withProxy).toHaveProperty('proxyType')

    const esteServidor = body(
      form({ type: 'FWD', name: 'x', forwarder: 'this-server' }),
      ctxDe(original),
    )
    expect(esteServidor).not.toHaveProperty('proxyType')
  })

  it('the alert says \"to update the record\"', () => {
    const original = reg('A', { ipAddress: '10.0.0.1' })
    expect(error(form({ type: 'A', name: 'www' }), ctxDe(original)).text).toBe(
      'Please enter an IP address to update the record.',
    )
  })

  it('the alert of an unknown type DOES carry the article when editing', () => {
    const original = reg('TYPE65280', { value: 'ABCD' })
    expect(error(form({ type: 'Unknown', unknownType: 'TYPE65280' }), ctxDe(original)).text).toBe(
      'Please enter a hex value as the RDATA to update the record.',
    )
  })
})

describe('SOA — it is only edited, and validates seven fields in order', () => {
  const original = reg('SOA', {})
  const ctx: RecordContext = { zone: 'casa.test', mode: 'update', original, updateSvcbHints: false }

  it('the order is primary, responsible, serial, refresh, retry, expire and minimum', () => {
    const fields = [
      'soaPrimaryNameServer',
      'soaResponsiblePerson',
      'soaSerial',
      'soaRefresh',
      'soaRetry',
      'soaExpire',
      'soaMinimum',
    ] as const

    const accumulated: Partial<RecordForm> = { type: 'SOA', name: '@' }
    for (const field of fields) {
      expect(error(form(accumulated), ctx).field).toBe(field)
      accumulated[field] = 'x'
    }
  })
})

describe('parameters of an SVCB', () => {
  it('they flatten as key|value', () => {
    const r = serializeSvcParams([
      { key: 'alpn', value: 'h2' },
      { key: 'port', value: '443' },
    ])
    expect(r).toEqual({ value: 'alpn|h2|port|443' })
  })

  it('an empty list travels as the string \"false\"', () => {
    expect(serializeSvcParams([])).toEqual({ value: 'false' })
  })

  it('an empty cell is an alert, not a row that gets ignored', () => {
    const r = serializeSvcParams([{ key: 'alpn', value: '' }])
    expect(r).toEqual({
      error: expect.objectContaining({
        text: 'Please enter a valid value in the text field in focus.',
      }),
    })
  })

  it('a vertical bar inside a cell too', () => {
    const r = serializeSvcParams([{ key: 'alpn', value: 'h2|h3' }])
    expect(r).toEqual({
      error: expect.objectContaining({
        text: "Please edit the value in the text field in focus to remove '|' character.",
      }),
    })
  })
})

describe('filling the form from a record', () => {
  it('the name is shown relative to the zone', () => {
    expect(formFromRecord(reg('A', { ipAddress: '1.1.1.1' }), 'casa.test').name).toBe('www')
  })

  it('the apex is shown as @', () => {
    const r = reg('SOA', {}, { name: 'casa.test' })
    expect(formFromRecord(r, 'casa.test').name).toBe('@')
  })

  it('an SVCB with an empty target is shown as the root', () => {
    const r = reg('SVCB', { svcPriority: 1, svcTargetName: '', svcParams: { alpn: 'h2' } })
    const f = formFromRecord(r, 'casa.test')
    expect(f.svcbTargetName).toBe('.')
    expect(f.svcbParams).toEqual([{ key: 'alpn', value: 'h2' }])
  })

  it('the glue of an NS is shown one address per line', () => {
    const r = reg('NS', { nameServer: 'ns1' }, { glueRecords: ['10.0.0.1', '10.0.0.2'] })
    expect(formFromRecord(r, 'casa.test').nsGlue).toBe('10.0.0.1\n10.0.0.2')
  })
})
