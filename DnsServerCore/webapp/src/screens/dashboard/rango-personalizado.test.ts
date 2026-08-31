import { describe, expect, it } from 'vitest'
import { instantesDelRango, loQueFalta } from './rango-personalizado'

describe('instantesDelRango', () => {
  /*
  La regla de los siete días de upstream (`main.js:2604-2612`): hasta una
  semana, la fecha se interpreta en la zona local —el servidor devuelve por
  horas y hay que alinearlas con el reloj de quien mira—; a partir de ahí, en
  UTC, que es como agrupa los días.
  */
  it('a partir de siete días interpreta las fechas en UTC', () => {
    const r = instantesDelRango('2026-08-01', '2026-08-20')
    expect(r.start).toBe('2026-08-01T00:00:00.000Z')
    expect(r.end).toBe('2026-08-20T00:00:00.000Z')
  })

  it('hasta siete días las interpreta en la zona local', () => {
    const r = instantesDelRango('2026-08-01', '2026-08-05')
    // No se clava una zona: se afirma que coincide con la medianoche LOCAL.
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
