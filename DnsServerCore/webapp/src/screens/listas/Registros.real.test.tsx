import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Registros } from './Registros'
import type { NodoLista, RegistroDns } from '../../api/zonelists'
import muestra from './muestra-real.json'

/*
La prueba que sostiene toda la fase.

Upstream vuelca el JSON entero dentro de un `<pre>`; nosotros lo pintamos como
tabla. Eso sólo es legítimo si NO se pierde ni un campo por el camino, y eso no
se puede comprobar con un registro inventado: hay que hacerlo con la respuesta
de verdad.

`muestra-real.json` son cinco nodos capturados de una instancia v15.4 (la de
`dev/`, en 127.0.0.1:5381) con `cache/list` y `allowed/list`: la raíz, `com`,
`example.com`, `technitium.com` y un nodo de la lista de permitidos. Entre los
cinco salen A, NS, SOA, DS y DNSKEY, y aparecen `responseMetadata`,
`nameServerMetadata`, `dnssecRecords`, `glueRecords`, `disabled`, `lastModified`
y `expiryTtl`. Para volver a capturarla: ver el bloque de curl de CONVENCIONES.md.
*/

const NODOS = muestra as unknown as Record<string, NodoLista>

/** Todos los valores escalares de un objeto, en profundidad. */
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
  // Los valores largos salen truncados: se despliegan todos antes de mirar.
  for (const b of screen.queryAllByRole('button', { name: 'ver completa' })) {
    await userEvent.click(b)
  }
  // Y las firmas DNSSEC y los glue records viven tras su botón.
  for (const nombre of ['RRSIG', 'Glue']) {
    for (const b of screen.queryAllByRole('button', { name: nombre })) {
      await userEvent.click(b)
    }
  }
  return container
}

describe('la tabla no pierde nada del JSON real', () => {
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
Los tres únicos campos que NO salen con su valor literal, y por qué. Están aquí
escritos a propósito: si algún día alguien cambia el criterio, esta prueba se lo
recuerda.
*/
describe('los tres campos que se dicen de otra forma', () => {
  it('la marca de tiempo completa se recorta a minutos, pero se conserva entera en el title', async () => {
    const nodo = NODOS.cacheTechnitium
    const c = await pintarTodo(nodo, true)
    const completa = (nodo.records[0] as RegistroDns).lastUsedOn!
    expect(c.textContent).toContain(completa.slice(0, 16).replace('T', ' '))
    expect(c.querySelector(`[title="${completa}"]`)).not.toBeNull()
  })

  it('`expiryTtl: 0` se dice «sin caducidad», que es lo que significa', async () => {
    const nodo = NODOS.allowed
    expect((nodo.records[0] as RegistroDns).expiryTtl).toBe(0)
    const c = await pintarTodo(nodo, false)
    expect(c.textContent).toContain('sin caducidad')
  })

  it('`disabled: false` no se dice: sólo se marca cuando es cierto', async () => {
    const nodo = NODOS.allowed
    expect((nodo.records[0] as RegistroDns).disabled).toBe(false)
    const c = await pintarTodo(nodo, false)
    expect(c.textContent).not.toContain('deshabilitado')
  })
})

/*
La red de seguridad de verdad: no basta con que salgan los campos que hoy
conocemos, tiene que salir CUALQUIER campo. Si el servidor añade uno mañana,
`extras` lo pinta solo y esta prueba lo demuestra sobre un registro real.
*/
describe('un campo que el servidor añada mañana', () => {
  it('aparece sin tocar nada', async () => {
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
