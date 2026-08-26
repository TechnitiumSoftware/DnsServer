import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { Th, useOrden, type Claves } from './Table'

/*
La regla de upstream (`sortTable`, common.js:228-280) no es un interruptor: la
pulsación ordena ascendente SALVO que la columna ya esté ascendente, y entonces
baja. La diferencia se nota justo en la primera pulsación.
*/

interface Fila {
  nombre: string
}

const CLAVES: Claves<Fila> = { nombre: (f) => f.nombre }

function Tabla({ datos }: { datos: Fila[] }) {
  const { filas, orden, alternar } = useOrden(CLAVES, datos)
  return (
    <table>
      <thead>
        <tr>
          <Th campo="nombre" orden={orden} onOrdenar={alternar}>
            Nombre
          </Th>
        </tr>
      </thead>
      <tbody>
        {filas.map((f) => (
          <tr key={f.nombre}>
            <td>{f.nombre}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function textos() {
  return screen.getAllByRole('cell').map((c) => c.textContent)
}

describe('ordenación de tabla', () => {
  it('desordenada: la primera pulsación ordena ascendente', async () => {
    render(<Tabla datos={[{ nombre: 'c' }, { nombre: 'a' }, { nombre: 'b' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Nombre/ }))
    expect(textos()).toEqual(['a', 'b', 'c'])
  })

  it('ya ascendente: la primera pulsación la da la vuelta, como upstream', async () => {
    render(<Tabla datos={[{ nombre: 'a' }, { nombre: 'b' }, { nombre: 'c' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Nombre/ }))
    expect(textos()).toEqual(['c', 'b', 'a'])
  })

  it('pulsar dos veces vuelve a subir, y lo anuncia con aria-sort', async () => {
    render(<Tabla datos={[{ nombre: 'c' }, { nombre: 'a' }]} />)
    const th = screen.getByRole('columnheader')
    const boton = screen.getByRole('button', { name: /Nombre/ })

    expect(th).toHaveAttribute('aria-sort', 'none')
    await userEvent.click(boton)
    expect(th).toHaveAttribute('aria-sort', 'ascending')
    await userEvent.click(boton)
    expect(th).toHaveAttribute('aria-sort', 'descending')
  })

  it('ordena por el texto que se ve, sin distinguir mayúsculas', async () => {
    render(<Tabla datos={[{ nombre: 'Zeta' }, { nombre: 'alfa' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Nombre/ }))
    expect(textos()).toEqual(['alfa', 'Zeta'])
  })
})
