import { describe, expect, it } from 'vitest'
import { serializeTable, type Cell } from './table-serialise'

const t = (value: string): Cell => ({ type: 'text', value })
const c = (value: boolean): Cell => ({ type: 'casilla', value })

describe('serializeTable', () => {
  it('with no rows it produces the empty string, not "false"', () => {
    expect(serializeTable([])).toEqual({ ok: true, value: '' })
  })

  it('it uses `|` between columns as well as between rows', () => {
    const r = serializeTable([
      [t('ana'), c(true), c(false), c(false)],
      [t('luis'), c(true), c(true), c(true)],
    ])
    expect(r).toEqual({ ok: true, value: 'ana|true|false|false|luis|true|true|true' })
  })

  it('a checkbox serialises as "true" or "false", never empty', () => {
    expect(serializeTable([[c(false)]])).toEqual({ ok: true, value: 'false' })
  })

  it('an empty text field aborts with the literal alert of upstream', () => {
    const r = serializeTable([[t('openid')], [t('')]])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.failure.title).toBe('Missing!')
    expect(r.failure.text).toBe('Please enter a valid value in the text field in focus.')
    expect(r.failure).toMatchObject({ row: 1, column: 0 })
  })

  it('a `|` inside a field aborts with its own alert', () => {
    const r = serializeTable([[t('remoto'), t('mal|valor')]])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.failure.title).toBe('Invalid Character!')
    expect(r.failure.text).toBe(
      "Please edit the value in the text field in focus to remove '|' character.",
    )
    expect(r.failure).toMatchObject({ row: 0, column: 1 })
  })
})
