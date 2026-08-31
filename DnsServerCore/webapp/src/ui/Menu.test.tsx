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
function Sample({ asRow = false }: { asRow?: boolean } = {}) {
  return (
    <Menu label="Opciones" rotulo="Opciones" asRow={asRow}>
      {(close) => (
        <>
          <button role="menuitem" onClick={close}>Uno</button>
          <button role="menuitem" onClick={close}>Dos</button>
        </>
      )}
    </Menu>
  )
}

describe('Menu', () => {
  it('resizing the window with the menu open closes it, and does not blow up', async () => {
    render(<Sample />)
    await userEvent.click(screen.getByRole('button', { name: 'Opciones' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()

    fireEvent(window, new Event('resize'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('it reports on opening, for whoever needs to check the state just before', async () => {
    const openOnes: number[] = []
    render(
      <Menu label="Opciones" rotulo="Opciones" onOpen={() => openOnes.push(1)}>
        {() => <button role="menuitem">Uno</button>}
      </Menu>,
    )
    const b = screen.getByRole('button', { name: 'Opciones' })
    await userEvent.click(b)
    await userEvent.click(b) // cerrar no avisa
    await userEvent.click(b)
    expect(openOnes).toHaveLength(2)
  })

  it('Escape closes it and returns the focus to the trigger', async () => {
    render(<Sample />)
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
  it('the row trigger closes on an outside click, just like the button one', async () => {
    render(
      <>
        <Sample asRow />
        <p>outside</p>
      </>,
    )
    await userEvent.click(screen.getByRole('button', { name: 'Opciones' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByText('outside'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
