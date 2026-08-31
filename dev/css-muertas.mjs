/*
CSS rules written and never applied.

This is the defect no test sees and no screenshot gives away: a class declared in
a module that no component references. It happened with `.v`, `.p` and `.k` on
the Dashboard tiles, which had gone unapplied since phase 1.

It is static on purpose. Sweeping the DOM would produce false positives for
everything living in a state the session never reached (a closed dialog, an empty
table, a hover).

## Why it resolves the import instead of just searching for the name

The first version treated any class as alive if its name appeared in ANY file
under `src/`. Its comment claimed the only possible error was staying silent
about a dead class, never inventing one, and that was true — but it stayed silent
about many: `.fail` was declared in four modules and used in one, and the other
three copies passed because the word existed in Settings. Unifying the panel-form
kit surfaced half a dozen leftovers that way.

Now it resolves which module each `styles` in each file points at, following the
two hops this codebase has: the direct import and the re-export
(`export { default as settingsStyles } from './Settings.module.css'`, used by the
nine Settings sub-tabs). Whatever cannot be resolved is not judged.

    node dev/css-muertas.mjs
*/
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'

const ROOT = join(import.meta.dirname, '..', 'DnsServerCore', 'webapp', 'src')

function files(dir, filter, acc = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) files(p, filter, acc)
    else if (filter.test(e)) acc.push(p)
  }
  return acc
}

const modules = files(ROOT, /\.module\.css$/)
const sources = files(ROOT, /\.tsx?$/).filter((f) => !/\.test\./.test(f))
const code = new Map(sources.map((f) => [f, readFileSync(f, 'utf8')]))

/** Resolves a relative import to a real file under `src/`. */
function resolveImport(from, rel) {
  const base = resolve(dirname(from), rel)
  for (const cand of [base, `${base}.tsx`, `${base}.ts`, join(base, 'index.tsx')]) {
    if (existsSync(cand) && statSync(cand).isFile()) return cand
  }
  return null
}

/*
Step 1: which module each file brings in under its own name, and under what name
it re-exports it. `alias` is what that file writes; `exposes` is the name another
file can ask for it by.
*/
const alias = new Map() // file -> Map(identifier -> module)
const exposes = new Map() // file -> Map(exported name -> module)
for (const [f, src] of code) {
  const a = new Map()
  const e = new Map()
  for (const m of src.matchAll(/import\s+(\w+)\s+from\s+['"]([^'"]*\.module\.css)['"]/g)) {
    a.set(m[1], resolve(dirname(f), m[2]))
  }
  for (const m of src.matchAll(
    /export\s*\{\s*default\s+as\s+(\w+)\s*\}\s*from\s*['"]([^'"]*\.module\.css)['"]/g,
  )) {
    e.set(m[1], resolve(dirname(f), m[2]))
  }
  for (const m of src.matchAll(/export\s*\{\s*(\w+)\s+as\s+(\w+)\s*\}/g)) {
    if (a.has(m[1])) e.set(m[2], a.get(m[1]))
  }
  alias.set(f, a)
  exposes.set(f, e)
}

/* Step 2: the indirect hop — `import { settingsStyles as styles } from '../parts'`. */
for (const [f, src] of code) {
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"](\.[^'"]*)['"]/g)) {
    const target = resolveImport(f, m[2])
    if (!target || !exposes.has(target)) continue
    for (const piece of m[1].split(',')) {
      const [, name, local] = /^\s*(\w+)(?:\s+as\s+(\w+))?\s*$/.exec(piece.trim()) ?? []
      if (name && exposes.get(target).has(name)) {
        alias.get(f).set(local ?? name, exposes.get(target).get(name))
      }
    }
  }
}

/*
A module consumed with brackets —`styles[variant]`— can use any class, so it is
not judged. You have to look at the identifier EACH file imports its module
under: the Dashboard calls a data object `s` and does `s[m.k]`, which has nothing
to do with its styles.
*/
const dynamic = new Set()
for (const [f, src] of code) {
  for (const [id, mod] of alias.get(f)) {
    if (new RegExp(`\\b${id}\\[`).test(src)) dynamic.add(mod)
  }
}

/* Step 3: which classes each module names, now properly attributed. */
const named = new Map(modules.map((m) => [m, new Set()]))
const consumers = new Map(modules.map((m) => [m, new Set()]))
for (const [f, src] of code) {
  for (const [id, mod] of alias.get(f)) {
    if (!named.has(mod)) continue
    consumers.get(mod).add(f)
    for (const m of src.matchAll(new RegExp(`\\b${id}\\.(\\w+)`, 'g'))) {
      named.get(mod).add(m[1])
    }
  }
}

/*
Four places in a CSS file look like they declare a class and declare none: the
comments (`.zt` lived in one), the contents of `url()` —where `www.w3.org` reads
as `.w3`—, the `:global()` blocks, and the path of a `composes: … from '…'`,
which ends in `.module.css` and would read as two classes, `.module` and `.css`.
They are stripped before looking.
*/
const strip = (css) =>
  css
    .replaceAll(/\/\*[\s\S]*?\*\//g, '')
    .replaceAll(/url\((?:[^()]|\([^()]*\))*\)/g, '')
    .replaceAll(/:global\([^)]*\)/g, '')
    .replaceAll(/(['"])(?:(?!\1).)*\1/g, "''")

/* And a class is also alive if another module inherits it with `composes: x from '…'`. */
const composed = new Map(modules.map((m) => [m, new Set()]))
for (const mod of modules) {
  // No `strip` here: that removes strings, and the `from` path is one.
  const css = readFileSync(mod, 'utf8').replaceAll(/\/\*[\s\S]*?\*\//g, '')
  for (const m of css.matchAll(/composes:\s*([\w\s-]+?)\s+from\s*['"]([^'"]+)['"]/g)) {
    const target = resolve(dirname(mod), m[2])
    if (!composed.has(target)) continue
    for (const c of m[1].trim().split(/\s+/)) composed.get(target).add(c)
  }
}

let dead = 0
let total = 0
const unjudged = new Set()

for (const mod of modules) {
  const css = readFileSync(mod, 'utf8')
  const declared = new Set()
  for (const m of strip(css).matchAll(/\.(-?[A-Za-z_][\w-]*)/g)) declared.add(m[1])
  total += declared.size

  if (dynamic.has(mod)) {
    unjudged.add(`${mod.slice(ROOT.length + 1)} (bracket access: not judged)`)
    continue
  }
  if (consumers.get(mod).size === 0 && composed.get(mod).size === 0) {
    unjudged.add(`${mod.slice(ROOT.length + 1)} (no resolved consumer: not judged)`)
    continue
  }

  const alive = new Set([...named.get(mod), ...composed.get(mod)])
  const unused = [...declared].filter((c) => !alive.has(c))

  if (unused.length) {
    dead += unused.length
    console.log(`\n${mod.slice(ROOT.length + 1)}  —  ${consumers.get(mod).size} consumer(s)`)
    for (const c of unused) {
      const line = css.split('\n').findIndex((l) => l.includes(`.${c}`)) + 1
      console.log(`  .${c}  (line ${line})`)
    }
  }
}

console.log(`\n${dead} classes declared and never named, out of ${total} in ${modules.length} modules`)
if (unjudged.size) {
  console.log('\nNot judged:')
  for (const d of unjudged) console.log(`  ${d}`)
}
