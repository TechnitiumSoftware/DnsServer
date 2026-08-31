import { describe, expect, it } from 'vitest'
import { addToList, addToTable } from './table'

describe('anadirALaLista — the "Add User" / "Add Group" dropdowns', () => {
  it('"blank" touches nothing', () => {
    expect(addToList('Ops\n', 'blank')).toBe('Ops\n')
  })

  it('"none" empties the whole list', () => {
    expect(addToList('Ops\nDev\n', 'none')).toBe('')
  })

  it('it appends at the end with its newline', () => {
    expect(addToList('', 'Ops')).toBe('Ops\n')
    expect(addToList('Ops\n', 'Dev')).toBe('Ops\nDev\n')
  })

  it('it guarantees the newline if the text did not carry one', () => {
    expect(addToList('Ops', 'Dev')).toBe('Ops\nDev\n')
  })

  it('it does not duplicate an entry that was already there', () => {
    expect(addToList('Ops\nDev\n', 'Ops')).toBe('Ops\nDev\n')
  })
})

describe('anadirALaTabla — the dropdowns of the permissions modal', () => {
  const blank = (name: string) => ({ name, canView: false })

  it('"blank" touches nothing and "none" empties the table', () => {
    const rows = [{ name: 'ana', canView: true }]
    expect(addToTable(rows, 'blank', blank)).toBe(rows)
    expect(addToTable(rows, 'none', blank)).toEqual([])
  })

  it('it adds the row with the permissions false', () => {
    expect(addToTable([], 'ana', blank)).toEqual([{ name: 'ana', canView: false }])
  })

  it('it does not add a row that already exists', () => {
    const rows = [{ name: 'ana', canView: true }]
    expect(addToTable(rows, 'ana', blank)).toBe(rows)
  })
})
