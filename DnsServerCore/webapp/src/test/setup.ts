import '@testing-library/jest-dom/vitest'

/*
`localStorage` en el entorno de pruebas.

Node 26 trae un `localStorage` nativo deshabilitado salvo que se arranque el
proceso con --localstorage-file, y en esta combinación de versiones (Node 26 +
vitest 4 + jsdom) tampoco lo expone jsdom: tanto `globalThis.localStorage` como
`window.localStorage` salen `undefined` con un origen perfectamente válido
(http://localhost:3000/).

Se instala aquí un Storage mínimo en memoria. Es una pieza del ENTORNO DE
PRUEBAS: no viaja al bundle ni cambia el código de la consola, que usa el
`localStorage` real del navegador.
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
