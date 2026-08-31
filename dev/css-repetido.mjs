/*
The same thing, written in two modules.

`css-muertas.mjs` answers whether a rule is unused. This one answers something
different: whether the SAME rule is written more than once. That is the defect
that produces drift —two copies that start identical and stop being identical—
and no screen-by-screen review catches it, because on each screen, taken alone,
everything looks right.

Measured before fixing it, it found 27 groups, and out of those came, among
others:

  · eleven `<textarea>` elements painting their own box by hand, with radius 6
    instead of 8 and without the inset shadow every other field carries;
  · the inline `<code>` in five modules and the intro paragraph in five, one of
    them at 1.65 line-height against 1.6 in the other four;
  · the `<details>` chevron hand-encoded as an SVG in a `data:` URI, in two
    modules, with a different stroke width from every other icon;
  · the count under a table sitting at four different distances.

    node dev/css-repetido.mjs

## How to read it

It groups by rule BODY, ignoring `composes`, and only shows bodies that appear in
more than one module. That leaves out what is already shared —a class that
composes from another repeats nothing— and leaves in three things that are NOT
defects, so look before you touch:

  · **Applying the same token.** Two components with `background: var(--acc)`
    duplicate nothing: the token IS the single source, and `composes` cannot even
    reach a pseudo-class or an attribute selector, which is where nearly all of
    these come from. Real example: the highlight on a menu option and the one on
    a dropdown option.
  · **Generic layout coincidences.** `display:flex; flex-direction:column;
    gap:var(--s-9)` shows up in a column on About, another on the Dashboard and
    the Login form. They are not the same thing; there are just few ways to stack
    three elements.
  · **The same responsive collapse.** `grid-template-columns: minmax(0,1fr)`
    inside a media query means "one column when narrow", and every grid in the
    console says it.

The minimum body length is there so the output is not drowned in single-property
rules, which are almost always one of the three cases above.
*/
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(import.meta.dirname, '..', 'DnsServerCore', 'webapp', 'src')
const MINIMUM = Number(process.env.MINIMO ?? 28)

function files(dir, acc = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) files(p, acc)
    else if (e.endsWith('.module.css')) acc.push(p)
  }
  return acc
}

const groups = new Map()

for (const mod of files(ROOT)) {
  const css = readFileSync(mod, 'utf8').replaceAll(/\/\*[\s\S]*?\*\//g, '')
  for (const m of css.matchAll(/([^{}]+)\{([^{}]+)\}/g)) {
    const selector = m[1].trim().split('\n').at(-1).trim()
    /* Normalised: no spaces and sorted, so two identical rules written with
       different formatting —or with the properties in another order— match. */
    const body = m[2]
      .split(';')
      .map((d) => d.trim().replaceAll(' ', ''))
      .filter((d) => d && !d.startsWith('composes'))
      .sort()
      .join(' ')
    if (body.length < MINIMUM) continue
    if (!groups.has(body)) groups.set(body, [])
    groups.get(body).push({ mod: mod.slice(ROOT.length + 1), selector })
  }
}

const repeated = [...groups]
  .filter(([, places]) => new Set(places.map((s) => s.mod)).size > 1)
  .sort((a, b) => b[1].length - a[1].length)

for (const [body, places] of repeated) {
  console.log(`\n[${places.length}] ${body}`)
  for (const s of places) console.log(`     ${s.mod}  ${s.selector}`)
}

console.log(`\n${repeated.length} rule bodies written in more than one module`)
