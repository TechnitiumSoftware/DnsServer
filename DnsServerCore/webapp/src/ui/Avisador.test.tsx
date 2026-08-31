import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Avisador } from './Avisador'

/*
The air it leaves beneath is measured in the browser, not here: jsdom does not lay
out. What it can answer is the contract, which is what fifty places were writing by
hand —and out of that came four distances for the same thing—.
*/
describe('Avisador', () => {
  it('sin aviso no pinta nada', () => {
    const { container } = render(<Avisador aviso={null} onCerrar={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('con aviso pinta título, texto y el botón de cerrar', async () => {
    const cerrar = vi.fn()
    render(
      <Avisador
        aviso={{ type: 'danger', title: 'Error!', text: 'Zone not found.' }}
        onCerrar={cerrar}
      />,
    )
    expect(screen.getByText('Error!')).toBeInTheDocument()
    expect(screen.getByText('Zone not found.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button'))
    expect(cerrar).toHaveBeenCalledOnce()
  })
})
