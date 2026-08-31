import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Notifier } from './Avisador'

/*
The air it leaves beneath is measured in the browser, not here: jsdom does not lay
out. What it can answer is the contract, which is what fifty places were writing by
hand —and out of that came four distances for the same thing—.
*/
describe('Notifier', () => {
  it('with no alert it draws nothing', () => {
    const { container } = render(<Notifier notice={null} onClose={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('with an alert it draws title, text and the close button', async () => {
    const close = vi.fn()
    render(
      <Notifier
        notice={{ type: 'danger', title: 'Error!', text: 'Zone not found.' }}
        onClose={close}
      />,
    )
    expect(screen.getByText('Error!')).toBeInTheDocument()
    expect(screen.getByText('Zone not found.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button'))
    expect(close).toHaveBeenCalledOnce()
  })
})
