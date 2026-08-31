import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  signZone,
  unsignZone,
  verDs,
  getPropiedades,
  addPrivateKey,
  updatePrivateKey,
  deletePrivateKey,
  publishAllPrivateKeys,
  activateKskDnsKey,
  rolloverDnsKey,
  retireDnsKey,
  convertToNSEC,
  convertToNSEC3,
  updateNSEC3Params,
  updateDnsKeyTtl,
  planNxProof,
} from './dnssec'
import * as client from './client'

afterEach(() => vi.restoreAllMocks())
const env = (r: unknown) => ({ kind: 'ok' as const, data: { status: 'ok', response: r } })

const firmaBase = { dnsKeyTtl: '3600', zskRolloverDays: '30', nxProof: 'NSEC' as const }

describe('signing and unsigning', () => {
  it('ECDSA sends `curve` and NOT the RSA parameters', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await signZone('t', 'casa.test', { ...firmaBase, algorithm: 'ECDSA', curve: 'P256' })
    const body = spy.mock.calls[0][1]?.body
    expect(spy.mock.calls[0][0]).toBe('zones/dnssec/sign')
    expect(body).toMatchObject({ algorithm: 'ECDSA', curve: 'P256' })
    expect(body).not.toHaveProperty('hashAlgorithm')
    expect(body).not.toHaveProperty('kskKeySize')
  })

  it('RSA sends hash and sizes, and NOT `curve`', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await signZone('t', 'casa.test', {
      ...firmaBase,
      algorithm: 'RSA',
      hashAlgorithm: 'SHA256',
      kskKeySize: '2048',
      zskKeySize: '1280',
    })
    const body = spy.mock.calls[0][1]?.body
    expect(body).toMatchObject({ hashAlgorithm: 'SHA256', kskKeySize: '2048', zskKeySize: '1280' })
    expect(body).not.toHaveProperty('curve')
  })

  it('NSEC3 adds iterations and salt; NSEC does not send them', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await signZone('t', 'casa.test', {
      ...firmaBase,
      algorithm: 'ECDSA',
      curve: 'P256',
      nxProof: 'NSEC3',
      iterations: '5',
      saltLength: '8',
    })
    expect(spy.mock.calls[0][1]?.body).toMatchObject({ iterations: '5', saltLength: '8' })

    await signZone('t', 'casa.test', { ...firmaBase, algorithm: 'ECDSA', curve: 'P256' })
    expect(spy.mock.calls[1][1]?.body).not.toHaveProperty('iterations')
  })

  it('the PEMs always travel, even when empty', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await signZone('t', 'casa.test', { ...firmaBase, algorithm: 'ECDSA', curve: 'P256' })
    expect(spy.mock.calls[0][1]?.body).toMatchObject({
      pemKskPrivateKey: '',
      pemZskPrivateKey: '',
    })
  })

  it('unsign only sends the zone and the node', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await unsignZone('t', 'casa.test')
    expect(spy.mock.calls[0][0]).toBe('zones/dnssec/unsign')
    expect(spy.mock.calls[0][1]?.body).toEqual({ zone: 'casa.test', node: '' })
  })
})

describe('lecturas', () => {
  it('viewDS tolerates there being no DS records', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ name: 'casa.test' }))
    expect(await verDs('t', 'casa.test')).toMatchObject({ dsRecords: [] })
  })

  it('properties/get tolerates there being no keys', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue(env({ name: 'casa.test', dnsKeyTtl: 3600 }))
    expect(await getPropiedades('t', 'casa.test')).toMatchObject({ dnssecPrivateKeys: [] })
  })

  it('both return null if the call fails', async () => {
    vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'error', message: 'x' })
    expect(await verDs('t', 'casa.test')).toBeNull()
    expect(await getPropiedades('t', 'casa.test')).toBeNull()
  })
})

describe('the nine actions on keys', () => {
  it('each one calls its endpoint with the keyTag as a string', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })

    await updatePrivateKey('t', 'casa.test', 47895, '30')
    await deletePrivateKey('t', 'casa.test', 47895)
    await publishAllPrivateKeys('t', 'casa.test')
    await activateKskDnsKey('t', 'casa.test', 47895)
    await rolloverDnsKey('t', 'casa.test', 47895)
    await retireDnsKey('t', 'casa.test', 47895)
    await updateDnsKeyTtl('t', 'casa.test', '7200')

    expect(spy.mock.calls.map((c) => c[0])).toEqual([
      'zones/dnssec/properties/updatePrivateKey',
      'zones/dnssec/properties/deletePrivateKey',
      'zones/dnssec/properties/publishAllPrivateKeys',
      'zones/dnssec/properties/activateKskDnsKey',
      'zones/dnssec/properties/rolloverDnsKey',
      'zones/dnssec/properties/retireDnsKey',
      'zones/dnssec/properties/updateDnsKeyTtl',
    ])
    expect(spy.mock.calls[0][1]?.body).toEqual({
      zone: 'casa.test',
      keyTag: '47895',
      rolloverDays: '30',
      node: '',
    })
    expect(spy.mock.calls[6][1]?.body).toMatchObject({ ttl: '7200' })
  })

  it('adding a key splits the parameters by algorithm, as when signing', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await addPrivateKey('t', 'casa.test', {
      keyType: 'KeySigningKey',
      algorithm: 'RSA',
      hashAlgorithm: 'SHA512',
      keySize: '4096',
      rolloverDays: '0',
    })
    const body = spy.mock.calls[0][1]?.body
    expect(spy.mock.calls[0][0]).toBe('zones/dnssec/properties/addPrivateKey')
    expect(body).toMatchObject({ hashAlgorithm: 'SHA512', keySize: '4096', pemPrivateKey: '' })
    expect(body).not.toHaveProperty('curve')
  })

  it('the three proof-of-non-existence changes go to their endpoint', async () => {
    const spy = vi.spyOn(client, 'apiRequest').mockResolvedValue({ kind: 'ok', data: {} })
    await convertToNSEC('t', 'casa.test')
    await convertToNSEC3('t', 'casa.test', '5', '8')
    await updateNSEC3Params('t', 'casa.test', '5', '8')
    expect(spy.mock.calls.map((c) => c[0])).toEqual([
      'zones/dnssec/properties/convertToNSEC',
      'zones/dnssec/properties/convertToNSEC3',
      'zones/dnssec/properties/updateNSEC3Params',
    ])
  })
})

describe('planNxProof — the decision table of changeDnssecNxProof', () => {
  const ceros = { iterations: '0', saltLength: '0' }

  it('NSEC → NSEC no llama a nadie', () => {
    expect(planNxProof('NSEC', 'NSEC', ceros, ceros)).toEqual({ action: 'ninguna' })
  })

  it('NSEC → NSEC3 converts, with the new values', () => {
    expect(planNxProof('NSEC', 'NSEC3', ceros, { iterations: '5', saltLength: '8' })).toEqual({
      action: 'convertToNSEC3',
      iterations: '5',
      saltLength: '8',
    })
  })

  it('NSEC3 → NSEC3 with no changes calls nobody', () => {
    const v = { iterations: '5', saltLength: '8' }
    expect(planNxProof('NSEC3', 'NSEC3', v, v)).toEqual({ action: 'ninguna' })
  })

  it('NSEC3 → NSEC3 with changes updates the parameters', () => {
    expect(
      planNxProof('NSEC3', 'NSEC3', { iterations: '5', saltLength: '8' }, { iterations: '6', saltLength: '8' }),
    ).toEqual({ action: 'updateNSEC3Params', iterations: '6', saltLength: '8' })
  })

  it('NSEC3 → NSEC converts back', () => {
    expect(planNxProof('NSEC3', 'NSEC', { iterations: '5', saltLength: '8' }, ceros)).toEqual({
      action: 'convertToNSEC',
    })
  })
})
