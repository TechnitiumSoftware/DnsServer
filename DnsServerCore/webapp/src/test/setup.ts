import '@testing-library/jest-dom/vitest'

/*
`localStorage` in the test environment.

Node 26 ships a native `localStorage` that is disabled unless the process is
started with --localstorage-file, and in this combination of versions (Node 26 +
vitest 4 + jsdom) jsdom does not expose it either: both `globalThis.localStorage`
and `window.localStorage` come out `undefined` with a perfectly valid origin
(http://localhost:3000/).

A minimal in-memory Storage is installed here. It is a piece of the TEST
ENVIRONMENT: it does not travel to the bundle and does not change the console's
code, which uses the browser's real `localStorage`.
*/
class MemoryStorage implements Storage {
  #map = new Map<string, string>()
  get length() { return this.#map.size }
  clear() { this.#map.clear() }
  getItem(key: string) { return this.#map.has(key) ? this.#map.get(key)! : null }
  key(index: number) { return Array.from(this.#map.keys())[index] ?? null }
  removeItem(key: string) { this.#map.delete(key) }
  setItem(key: string, value: string) { this.#map.set(key, String(value)) }
}

for (const name of ['localStorage', 'sessionStorage'] as const) {
  const existing = (globalThis as Record<string, unknown>)[name]
  if (existing == null) {
    const storage = new MemoryStorage()
    Object.defineProperty(globalThis, name, { value: storage, configurable: true, writable: true })
    if (typeof window !== 'undefined') {
      Object.defineProperty(window, name, { value: storage, configurable: true, writable: true })
    }
  }
}
