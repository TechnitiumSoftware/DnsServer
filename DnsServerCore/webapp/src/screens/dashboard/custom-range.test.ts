import { describe, expect, it } from 'vitest'
import { rangeInstants, loQueFalta } from './custom-range'

describe('rangeInstants', () => {
  /*
  Upstream's seven-day rule (`main.js:2604-2612`): up to a week, the date is read
  in the local zone —the server returns by the hour and those have to line up with
  the clock of whoever is looking— and beyond that, in UTC, which is how it groups
  the days.
  */
  it('beyond seven days it reads the dates in UTC', () => {
    const r = rangeInstants('2026-08-01', '2026-08-20')
    expect(r.start).toBe('2026-08-01T00:00:00.000Z')
    expect(r.end).toBe('2026-08-20T00:00:00.000Z')
  })

  it('up to seven days it reads them in the local zone', () => {
    const r = rangeInstants('2026-08-01', '2026-08-05')
    // No zone is pinned: it asserts that it matches LOCAL midnight.
    expect(r.start).toBe(new Date('2026-08-01T00:00:00').toISOString())
    expect(r.end).toBe(new Date('2026-08-05T00:00:00').toISOString())
  })

  it('the seventh day still falls on the local side, and the eighth no longer does', () => {
    const seven = rangeInstants('2026-08-01', '2026-08-07')
    const eight = rangeInstants('2026-08-01', '2026-08-08')
    expect(seven.start).toBe(new Date('2026-08-01T00:00:00').toISOString())
    expect(eight.start).toBe('2026-08-01T00:00:00.000Z')
  })
})

describe('loQueFalta', () => {
  it('it asks for the start first, with the upstream text', () => {
    expect(loQueFalta('', '')).toBe('Please select a start date.')
    expect(loQueFalta('', '2026-08-05')).toBe('Please select a start date.')
  })

  it('and the end second', () => {
    expect(loQueFalta('2026-08-01', '')).toBe('Please select an end date.')
  })

  it('with both filled in nothing is missing', () => {
    expect(loQueFalta('2026-08-01', '2026-08-05')).toBeNull()
  })
})
