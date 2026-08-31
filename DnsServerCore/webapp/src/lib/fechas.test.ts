import { describe, expect, it } from 'vitest'
import { fromNow, fechaHora, fechaMinuto } from './fechas'

/* The format is moment's: `YYYY-MM-DD HH:mm:ss` in LOCAL time. The tests build
   the date with `new Date(y, m, d, …)`, which is already local, so as not to
   depend on the time zone of whoever runs them. */

describe('fechaHora / fechaMinuto', () => {
  const d = new Date(2026, 7, 25, 16, 41, 12).toISOString()

  it('it zero-pads months, days, hours, minutes and seconds', () => {
    expect(fechaHora(new Date(2026, 0, 2, 3, 4, 5).toISOString())).toBe('2026-01-02 03:04:05')
  })

  it('the Cluster table cuts off at the minutes', () => {
    expect(fechaHora(d)).toBe('2026-08-25 16:41:12')
    expect(fechaMinuto(d)).toBe('2026-08-25 16:41')
  })

  it('an absent or unreadable date does not break the table: it returns an empty string', () => {
    expect(fechaHora(null)).toBe('')
    expect(fechaHora(undefined)).toBe('')
    expect(fechaHora('no es una fecha')).toBe('')
    expect(fechaMinuto(null)).toBe('')
  })
})

describe('desdeAhora — the moment literals', () => {
  const ahora = Date.UTC(2026, 7, 25, 12, 0, 0)
  const hace = (ms: number) => fromNow(new Date(ahora - ms).toISOString(), ahora)

  it('under 45 s it always says \"a few seconds ago\"', () => {
    expect(hace(0)).toBe('a few seconds ago')
    expect(hace(1000)).toBe('a few seconds ago')
    expect(hace(44_000)).toBe('a few seconds ago')
  })

  it('the threshold for \"a minute\" is at 45 s, not at 60', () => {
    expect(hace(45_000)).toBe('a minute ago')
    expect(hace(89_000)).toBe('a minute ago')
    expect(hace(91_000)).toBe('2 minutes ago')
  })

  it('minutes, hours and days', () => {
    expect(hace(8 * 60_000)).toBe('8 minutes ago')
    expect(hace(44 * 60_000)).toBe('44 minutes ago')
    expect(hace(60 * 60_000)).toBe('an hour ago')
    expect(hace(3 * 3600_000)).toBe('3 hours ago')
    expect(hace(24 * 3600_000)).toBe('a day ago')
    expect(hace(5 * 24 * 3600_000)).toBe('5 days ago')
  })

  it('months and years', () => {
    expect(hace(40 * 24 * 3600_000)).toBe('a month ago')
    expect(hace(120 * 24 * 3600_000)).toBe('4 months ago')
    expect(hace(400 * 24 * 3600_000)).toBe('a year ago')
    expect(hace(3 * 365 * 24 * 3600_000)).toBe('3 years ago')
  })

  it('a future date carries the \"in\" prefix, not the \"ago\" suffix', () => {
    expect(fromNow(new Date(ahora + 3 * 3600_000).toISOString(), ahora)).toBe('in 3 hours')
  })

  it('`0001-01-01T00:00:00` is the .NET \"never\" and comes out as years, it does not blow up', () => {
    expect(fromNow('0001-01-01T00:00:00', ahora)).toMatch(/ years ago$/)
  })
})
