import { describe, expect, it } from 'vitest'
import { anadirALaLista, anadirALaTabla } from './tabla'

describe('anadirALaLista — the "Add User" / "Add Group" dropdowns', () => {
  it('"blank" touches nothing', () => {
    expect(anadirALaLista('Ops\n', 'blank')).toBe('Ops\n')
  })

  it('"none" empties the whole list', () => {
    expect(anadirALaLista('Ops\nDev\n', 'none')).toBe('')
  })

  it('it appends at the end with its newline', () => {
    expect(anadirALaLista('', 'Ops')).toBe('Ops\n')
    expect(anadirALaLista('Ops\n', 'Dev')).toBe('Ops\nDev\n')
  })

  it('it guarantees the newline if the text did not carry one', () => {
    expect(anadirALaLista('Ops', 'Dev')).toBe('Ops\nDev\n')
  })

  it('it does not duplicate an entry that was already there', () => {
    expect(anadirALaLista('Ops\nDev\n', 'Ops')).toBe('Ops\nDev\n')
  })
})

describe('anadirALaTabla — the dropdowns of the permissions modal', () => {
  const nueva = (nombre: string) => ({ nombre, canView: false })

  it('"blank" touches nothing and "none" empties the table', () => {
    const filas = [{ nombre: 'ana', canView: true }]
    expect(anadirALaTabla(filas, 'blank', nueva)).toBe(filas)
    expect(anadirALaTabla(filas, 'none', nueva)).toEqual([])
  })

  it('it adds the row with the permissions false', () => {
    expect(anadirALaTabla([], 'ana', nueva)).toEqual([{ nombre: 'ana', canView: false }])
  })

  it('it does not add a row that already exists', () => {
    const filas = [{ nombre: 'ana', canView: true }]
    expect(anadirALaTabla(filas, 'ana', nueva)).toBe(filas)
  })
})
