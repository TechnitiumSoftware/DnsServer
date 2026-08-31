/*
`Proxy & Forwarders` → `proxy-forwarders`.

It lives on its own and not inside `ruta.ts` because both sides need it: the
browser to read the address bar, and `vite.config` to know which folders the build
has to emit. `ruta.ts` touches `window` and `document`, and the config's TypeScript
project has no DOM: a string function cannot drag that dependency along.
*/
export function aSlug(label: string): string {
  return label
    .toLowerCase()
    .replace(/&/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}
