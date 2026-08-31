import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Menu } from './Menu'

/*
De esta pieza, jsdom sólo puede contestar la mitad: no hay maquetación, así que
`getBoundingClientRect()` devuelve ceros y no tiene sentido afirmar aquí que el
menú se voltea cuando no cabe —eso está medido en el navegador, con la ventana a
900 y a 560 px—. Lo que sí puede contestar es la conducta, y en particular el
fallo que introdujo el volteo: el manejador que cierra el menú al rodar la
página lo comparte el `resize`, y ahí el `target` es `window`, que no es un
nodo.
*/
function Ejemplo() {
  return (
    <Menu etiqueta="Opciones" rotulo="Opciones">
      {(cerrar) => (
        <>
          <button role="menuitem" onClick={cerrar}>Uno</button>
          <button role="menuitem" onClick={cerrar}>Dos</button>
        </>
      )}
    </Menu>
  )
}

describe('Menu', () => {
  it('cambiar el tamaño de la ventana con el menú abierto lo cierra, y no revienta', async () => {
    render(<Ejemplo />)
    await userEvent.click(screen.getByRole('button', { name: 'Opciones' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()

    fireEvent(window, new Event('resize'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('avisa al abrir, para quien necesita mirar el estado justo antes', async () => {
    const abiertas: number[] = []
    render(
      <Menu etiqueta="Opciones" rotulo="Opciones" onAbrir={() => abiertas.push(1)}>
        {() => <button role="menuitem">Uno</button>}
      </Menu>,
    )
    const b = screen.getByRole('button', { name: 'Opciones' })
    await userEvent.click(b)
    await userEvent.click(b) // cerrar no avisa
    await userEvent.click(b)
    expect(abiertas).toHaveLength(2)
  })

  it('Escape lo cierra y devuelve el foco al disparador', async () => {
    render(<Ejemplo />)
    const b = screen.getByRole('button', { name: 'Opciones' })
    await userEvent.click(b)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)
  })
})
