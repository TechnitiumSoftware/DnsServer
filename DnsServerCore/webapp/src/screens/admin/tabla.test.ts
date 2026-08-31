import { describe, expect, it } from 'vitest'
import { anadirALaLista, anadirALaTabla } from './tabla'

describe('anadirALaLista — los desplegables «Add User» / «Add Group»', () => {
  it('«blank» no toca nada', () => {
    expect(anadirALaLista('Ops\n', 'blank')).toBe('Ops\n')
  })

  it('«none» vacía la lista entera', () => {
    expect(anadirALaLista('Ops\nDev\n', 'none')).toBe('')
  })

  it('añade al final con su salto de línea', () => {
    expect(anadirALaLista('', 'Ops')).toBe('Ops\n')
    expect(anadirALaLista('Ops\n', 'Dev')).toBe('Ops\nDev\n')
  })

  it('garantiza el salto de línea si el texto no lo traía', () => {
    expect(anadirALaLista('Ops', 'Dev')).toBe('Ops\nDev\n')
  })

  it('no duplica una entrada que ya estaba', () => {
    expect(anadirALaLista('Ops\nDev\n', 'Ops')).toBe('Ops\nDev\n')
  })
})

describe('anadirALaTabla — los desplegables del modal de permisos', () => {
  const nueva = (nombre: string) => ({ nombre, canView: false })

  it('«blank» no toca nada y «none» vacía la tabla', () => {
    const filas = [{ nombre: 'ana', canView: true }]
    expect(anadirALaTabla(filas, 'blank', nueva)).toBe(filas)
    expect(anadirALaTabla(filas, 'none', nueva)).toEqual([])
  })

  it('añade la fila con los permisos a falso', () => {
    expect(anadirALaTabla([], 'ana', nueva)).toEqual([{ nombre: 'ana', canView: false }])
  })

  it('no añade una fila que ya existe', () => {
    const filas = [{ nombre: 'ana', canView: true }]
    expect(anadirALaTabla(filas, 'ana', nueva)).toBe(filas)
  })
})
