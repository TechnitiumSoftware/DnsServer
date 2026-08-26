import { describe, expect, it } from 'vitest'
import { anadirALaLista, anadirALaTabla, serializarTabla, type Celda } from './tabla'

const t = (valor: string): Celda => ({ tipo: 'texto', valor })
const c = (valor: boolean): Celda => ({ tipo: 'casilla', valor })

describe('serializarTabla', () => {
  it('sin filas produce la cadena vacía, no «false»', () => {
    expect(serializarTabla([])).toEqual({ ok: true, valor: '' })
  })

  it('usa `|` tanto entre columnas como entre filas', () => {
    const r = serializarTabla([
      [t('ana'), c(true), c(false), c(false)],
      [t('luis'), c(true), c(true), c(true)],
    ])
    expect(r).toEqual({ ok: true, valor: 'ana|true|false|false|luis|true|true|true' })
  })

  it('una casilla se serializa como «true» o «false», nunca vacía', () => {
    expect(serializarTabla([[c(false)]])).toEqual({ ok: true, valor: 'false' })
  })

  it('un campo de texto vacío aborta con el aviso literal de upstream', () => {
    const r = serializarTabla([[t('openid')], [t('')]])
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.fallo.title).toBe('Missing!')
    expect(r.fallo.text).toBe('Please enter a valid value in the text field in focus.')
    expect(r.fallo).toMatchObject({ fila: 1, columna: 0 })
  })

  it('un `|` dentro de un campo aborta con su propio aviso', () => {
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
