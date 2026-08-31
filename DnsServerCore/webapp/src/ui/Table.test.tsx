import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { Th, useOrden, type Keys } from './Table'

/*
Upstream's rule (`sortTable`, common.js:228-280) is not a toggle: a click sorts
ascending UNLESS the column is already ascending, in which case it goes down. The
difference shows precisely on the first click.
*/

interface Row {
  name: string
}

const KEYS: Keys<Row> = { name: (f) => f.name }

function Table({ data }: { data: Row[] }) {
  const { rows, sort, toggle } = useOrden(KEYS, data)
  return (
    <table>
      <thead>
        <tr>
          <Th field="name" sort={sort} onSort={toggle}>
            Name
          </Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f) => (
          <tr key={f.name}>
            <td>{f.name}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function textos() {
  return screen.getAllByRole('cell').map((c) => c.textContent)
}

describe('table sorting', () => {
  it('unsorted: the first click sorts ascending', async () => {
    render(<Table data={[{ name: 'c' }, { name: 'a' }, { name: 'b' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Name/ }))
    expect(textos()).toEqual(['a', 'b', 'c'])
  })

  it('already ascending: the first click turns it around, like upstream', async () => {
    render(<Table data={[{ name: 'a' }, { name: 'b' }, { name: 'c' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Name/ }))
    expect(textos()).toEqual(['c', 'b', 'a'])
  })

  it('clicking twice goes back up, and announces it with aria-sort', async () => {
    render(<Table data={[{ name: 'c' }, { name: 'a' }]} />)
    const th = screen.getByRole('columnheader')
    const button = screen.getByRole('button', { name: /Name/ })

    expect(th).toHaveAttribute('aria-sort', 'none')
    await userEvent.click(button)
    expect(th).toHaveAttribute('aria-sort', 'ascending')
    await userEvent.click(button)
    expect(th).toHaveAttribute('aria-sort', 'descending')
  })

  it('it sorts by the text you see, case-insensitively', async () => {
    render(<Table data={[{ name: 'Zeta' }, { name: 'alfa' }]} />)
    await userEvent.click(screen.getByRole('button', { name: /Name/ }))
    expect(textos()).toEqual(['alfa', 'Zeta'])
  })
})
