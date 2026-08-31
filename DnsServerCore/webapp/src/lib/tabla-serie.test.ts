import { describe, expect, it } from 'vitest'
import { serializarTabla, type Celda } from './tabla-serie'

const t = (valor: string): Celda => ({ tipo: 'texto', valor })
const c = (valor: boolean): Celda => ({ tipo: 'casilla', valor })

describe('serializarTabla', () => {
  it('with no rows it produces the empty string, not "false"', () => {
    expect(serializarTabla([])).toEqual({ ok: true, valor: '' })
  })

  it('it uses `|` between columns as well as between rows', () => {
    const r = serializarTabla([
      [t('ana'), c(true), c(false), c(false)],
      [t('luis'), c(true), c(true), c(true)],
    ])
    expect(r).toEqual({ ok: true, valor: 'ana|true|false|false|luis|true|true|true' })
  })

  it('a checkbox serialises as "true" or "false", never empty', () => {
    expect(serializarTabla([[c(false)]])).toEqual({ ok: true, valor: 'false' })
  })

  it('an empty text field aborts with the literal alert of upstream', () => {
    const r = serializarTabla([[t('openid')], [t('')]])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.fallo.title).toBe('Missing!')
    expect(r.fallo.text).toBe('Please enter a valid value in the text field in focus.')
    expect(r.fallo).toMatchObject({ fila: 1, columna: 0 })
  })

  it('a `|` inside a field aborts with its own alert', () => {
    const r = serializarTabla([[t('remoto'), t('mal|valor')]])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.fallo.title).toBe('Invalid Character!')
    expect(r.fallo.text).toBe(
      "Please edit the value in the text field in focus to remove '|' character.",
    )
    expect(r.fallo).toMatchObject({ fila: 0, columna: 1 })
  })
})
