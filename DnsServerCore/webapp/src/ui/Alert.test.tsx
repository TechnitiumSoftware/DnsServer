import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Alert } from './Alert'

/* common.js:213-217 — only success alerts dismiss themselves, and after 5 s. */

afterEach(() => vi.useRealTimers())

describe('auto-descarte del aviso', () => {
  it('un éxito se descarta solo a los cinco segundos', () => {
    vi.useFakeTimers()
    const cerrar = vi.fn()
    render(<Alert type="success" title="Saved!" onDismiss={cerrar} />)

    vi.advanceTimersByTime(4999)
    expect(cerrar).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(cerrar).toHaveBeenCalledTimes(1)
  })

  it('un error NO se descarta solo: el usuario tiene que leerlo', () => {
    vi.useFakeTimers()
    const cerrar = vi.fn()
    render(<Alert type="danger" title="Error!" onDismiss={cerrar} />)

    vi.advanceTimersByTime(30000)
    expect(cerrar).not.toHaveBeenCalled()
  })

  it('un éxito que no se puede cerrar tampoco se va solo', () => {
    vi.useFakeTimers()
    render(<Alert type="success" title="Saved!" />)
    vi.advanceTimersByTime(30000)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('un aviso nuevo reinicia el reloj', () => {
    vi.useFakeTimers()
    const cerrar = vi.fn()
    const { rerender } = render(<Alert type="success" title="Saved!" onDismiss={cerrar} />)

    vi.advanceTimersByTime(4000)
    rerender(<Alert type="success" title="Flushed!" onDismiss={cerrar} />)
    vi.advanceTimersByTime(4000)
    expect(cerrar).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1000)
    expect(cerrar).toHaveBeenCalledTimes(1)
  })
})
