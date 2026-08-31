import { describe, expect, it } from 'vitest'
import { instantesDelRango, loQueFalta } from './rango-personalizado'

describe('instantesDelRango', () => {
  /*
  Upstream's seven-day rule (`main.js:2604-2612`): up to a week, the date is read
  in the local zone —the server returns by the hour and those have to line up with
  the clock of whoever is looking— and beyond that, in UTC, which is how it groups
  the days.
  */
  it('a partir de siete días interpreta las fechas en UTC', () => {
    const r = instantesDelRango('2026-08-01', '2026-08-20')
    expect(r.start).toBe('2026-08-01T00:00:00.000Z')
    expect(r.end).toBe('2026-08-20T00:00:00.000Z')
  })

  it('hasta siete días las interpreta en la zona local', () => {
    const r = instantesDelRango('2026-08-01', '2026-08-05')
    // No zone is pinned: it asserts that it matches LOCAL midnight.
    expect(r.start).toBe(new Date('2026-08-01T00:00:00').toISOString())
    expect(r.end).toBe(new Date('2026-08-05T00:00:00').toISOString())
  })

  it('el séptimo día cae todavía del lado local, y el octavo ya no', () => {
    const siete = instantesDelRango('2026-08-01', '2026-08-07')
    const ocho = instantesDelRango('2026-08-01', '2026-08-08')
    expect(siete.start).toBe(new Date('2026-08-01T00:00:00').toISOString())
    expect(ocho.start).toBe('2026-08-01T00:00:00.000Z')
  })
})

describe('loQueFalta', () => {
  it('pide primero el inicio, con el texto de upstream', () => {
    expect(loQueFalta('', '')).toBe('Please select a start date.')
    expect(loQueFalta('', '2026-08-05')).toBe('Please select a start date.')
  })

  it('y después el fin', () => {
    expect(loQueFalta('2026-08-01', '')).toBe('Please select an end date.')
  })

  it('con las dos puestas no falta nada', () => {
    expect(loQueFalta('2026-08-01', '2026-08-05')).toBeNull()
  })
})
