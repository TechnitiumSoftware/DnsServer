import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Avisador } from './Avisador'

/*
El aire que deja debajo se mide en el navegador, no aquí: jsdom no maqueta. Lo
que sí puede contestar es el contrato, que es lo que cincuenta sitios escribían
a mano —y de ahí salieron cuatro distancias para lo mismo—.
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
