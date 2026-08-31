import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Alert } from './Alert'

/* common.js:213-217 — only success alerts dismiss themselves, and after 5 s. */

afterEach(() => vi.useRealTimers())

describe('self-dismissal of the alert', () => {
  it('a success dismisses itself after five seconds', () => {
    vi.useFakeTimers()
    const close = vi.fn()
    render(<Alert type="success" title="Saved!" onDismiss={close} />)

    vi.advanceTimersByTime(4999)
    expect(close).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(close).toHaveBeenCalledTimes(1)
  })

  it('an error does NOT dismiss itself: the user has to read it', () => {
    vi.useFakeTimers()
    const close = vi.fn()
    render(<Alert type="danger" title="Error!" onDismiss={close} />)

    vi.advanceTimersByTime(30000)
    expect(close).not.toHaveBeenCalled()
  })

  it('a success that cannot be closed does not go away by itself either', () => {
    vi.useFakeTimers()
    render(<Alert type="success" title="Saved!" />)
    vi.advanceTimersByTime(30000)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('a new alert restarts the clock', () => {
    vi.useFakeTimers()
    const close = vi.fn()
    const { rerender } = render(<Alert type="success" title="Saved!" onDismiss={close} />)

    vi.advanceTimersByTime(4000)
    rerender(<Alert type="success" title="Flushed!" onDismiss={close} />)
    vi.advanceTimersByTime(4000)
    expect(close).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1000)
    expect(close).toHaveBeenCalledTimes(1)
  })
})
