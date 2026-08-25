import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from '../App'

describe('andamiaje de pruebas', () => {
  it('renderiza la app', () => {
    render(<App />)
    expect(screen.getByText('technitium-ui')).toBeInTheDocument()
  })
})
