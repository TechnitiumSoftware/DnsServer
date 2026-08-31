import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Menu } from './Menu'

/*
For this piece, jsdom can only answer half: there is no layout, so
`getBoundingClientRect()` returns zeros and there is no point asserting here that
the menu flips when it does not fit —that is measured in the browser, with the
window at 900 and at 560 px—. What it can answer is the behaviour, and in
particular the bug the flipping introduced: the handler that closes the menu on
scroll is shared with `resize`, and there the `target` is `window`, which is not a
node.
*/
function Ejemplo({ comoFila = false }: { comoFila?: boolean } = {}) {
  return (
    <Menu etiqueta="Opciones" rotulo="Opciones" comoFila={comoFila}>
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

  /*
  The row trigger is the account one, at the foot of the sidebar. It was written
  separately, with its own state, and it had forgotten precisely the three things
  you cannot see by looking at it open: it did not close on an outside click, nor
  on Escape, nor on scroll. Now it is this same menu, so it inherits them; this
  test is what stops it being written on its own again.
  */
  it('el disparador de fila cierra al pulsar fuera, igual que el de botón', async () => {
    render(
      <>
        <Ejemplo comoFila />
        <p>fuera</p>
      </>,
    )
    await userEvent.click(screen.getByRole('button', { name: 'Opciones' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByText('fuera'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
