import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Registros } from './Registros'
import type { NodoLista, RegistroDns } from '../../api/zonelists'
import muestra from './muestra-real.json'

/*
The test that holds up the whole phase.

Upstream dumps the entire JSON inside a `<pre>`; we draw it as a table. That is
only legitimate if NOT a single field is lost along the way, and that cannot be
checked with an invented record: it has to be done with the real response.

`muestra-real.json` is five nodes captured from a v15.4 instance (the one in
`dev/`, at 127.0.0.1:5381) with `cache/list` and `allowed/list`: the root, `com`,
`example.com`, `technitium.com` and a node from the allowed list. Between the
five, A, NS, SOA, DS and DNSKEY come out, and `responseMetadata`,
`nameServerMetadata`, `dnssecRecords`, `glueRecords`, `disabled`, `lastModified`
and `expiryTtl` appear. To capture it again: see the curl block in
CONVENCIONES.md.
*/

const NODOS = muestra as unknown as Record<string, NodoLista>

/** Every scalar value of an object, in depth. */
function hojas(o: unknown): string[] {
  if (o == null) return []
  if (Array.isArray(o)) return o.flatMap(hojas)
  if (typeof o === 'object') return Object.values(o as Record<string, unknown>).flatMap(hojas)
  if (typeof o === 'boolean') return []
  return [String(o)]
}

async function pintarTodo(nodo: NodoLista, conDnssec: boolean) {
  const { container } = render(
    <Registros records={nodo.records} conDnssec={conDnssec} nodo={nodo.domain} />,
  )
  // The long values come out truncated: they are all expanded before looking.
  for (const b of screen.queryAllByRole('button', { name: 'show full' })) {
    await userEvent.click(b)
  }
  // And the DNSSEC signatures and the glue records live behind their button.
  for (const nombre of ['RRSIG', 'Glue']) {
    for (const b of screen.queryAllByRole('button', { name: nombre })) {
      await userEvent.click(b)
    }
  }
  return container
}

describe('the table loses nothing from the real JSON', () => {
  for (const [nombre, nodo] of Object.entries(NODOS)) {
    const conDnssec = nombre.startsWith('cache')

    it(`${nombre}: cada valor de rData sale en la tabla`, async () => {
      const c = await pintarTodo(nodo, conDnssec)
      const texto = c.textContent ?? ''
      for (const r of nodo.records) {
        for (const v of hojas(r.rData)) {
          expect(texto, `falta ${v} de un ${r.type}`).toContain(v)
        }
      }
    })

    it(`${nombre}: los metadatos y las firmas también`, async () => {
      const c = await pintarTodo(nodo, conDnssec)
      const texto = c.textContent ?? ''
      for (const r of nodo.records as RegistroDns[]) {
        for (const v of [
          ...hojas(r.responseMetadata),
          ...hojas(r.nameServerMetadata),
          ...hojas(r.dnssecRecords),
          ...hojas(r.glueRecords),
          ...hojas(r.eDnsClientSubnet),
        ]) {
          expect(texto, `falta ${v} de un ${r.type}`).toContain(v)
        }
        if (r.dnssecStatus) expect(texto).toContain(r.dnssecStatus)
      }
    })

    it(`${nombre}: el TTL sale con su número y su forma humana`, async () => {
      const c = await pintarTodo(nodo, conDnssec)
      const texto = c.textContent ?? ''
      for (const r of nodo.records as RegistroDns[]) {
        if (typeof r.ttl === 'string') {
          const [num, humano] = r.ttl.replace(')', '').split(' (')
          expect(texto).toContain(num)
          expect(texto).toContain(humano)
        } else {
          expect(texto).toContain(String(r.ttl))
          if (r.ttlString) expect(texto).toContain(r.ttlString)
        }
      }
    })
  }
})

/*
The only three fields that do NOT come out with their literal value, and why.
They are written here on purpose: if some day someone changes the criterion, this
test reminds them.
*/
describe('the three fields that are stated differently', () => {
  it('the full timestamp is trimmed to minutes, but kept whole in the title', async () => {
    const nodo = NODOS.cacheTechnitium
    const c = await pintarTodo(nodo, true)
    const completa = (nodo.records[0] as RegistroDns).lastUsedOn!
    expect(c.textContent).toContain(completa.slice(0, 16).replace('T', ' '))
    expect(c.querySelector(`[title="${completa}"]`)).not.toBeNull()
  })

  it('`expiryTtl: 0` is stated as "no expiry", which is what it means', async () => {
    const nodo = NODOS.allowed
    expect((nodo.records[0] as RegistroDns).expiryTtl).toBe(0)
    const c = await pintarTodo(nodo, false)
    expect(c.textContent).toContain('no expiry')
  })

  it('`disabled: false` is not stated: it is only marked when true', async () => {
    const nodo = NODOS.allowed
    expect((nodo.records[0] as RegistroDns).disabled).toBe(false)
    const c = await pintarTodo(nodo, false)
    expect(c.textContent).not.toContain('disabled')
  })
})

/*
The real safety net: it is not enough for the fields we know today to come out,
ANY field has to. If the server adds one tomorrow, `extras` draws it on its own
and this test proves it over a real record.
*/
describe('a field the server adds tomorrow', () => {
  it('it appears without touching anything', async () => {
    const base = NODOS.cacheExample.records[0] as RegistroDns
    const nodo: NodoLista = {
      domain: 'example.com',
      zones: [],
      records: [{ ...base, campoDelFuturo: 'valor-inesperado' }],
    }
    const c = await pintarTodo(nodo, true)
    expect(c.textContent).toContain('Campo del futuro')
    expect(c.textContent).toContain('valor-inesperado')
  })
})
