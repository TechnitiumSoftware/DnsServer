/*
Reglas CSS escritas y nunca aplicadas.

Este es el defecto que ninguna prueba ve y ninguna captura delata: una clase
declarada en un módulo que ningún componente referencia. Pasó con `.v`, `.p` y
`.k` de los tiles del Dashboard, que llevaban desde la fase 1 sin aplicarse.

Es estático a propósito. Barrer el DOM daría falsos positivos con todo lo que
vive en un estado al que la sesión no llegó (un diálogo cerrado, una tabla
vacía, un hover).

## Por qué resuelve el import y no busca el nombre a secas

La primera versión daba por viva cualquier clase cuyo nombre apareciera en
CUALQUIER fichero de `src/`. Su comentario decía que el único error posible era
callar una clase muerta, nunca inventarla, y era verdad — pero callaba muchas:
`.fail` estaba declarada en cuatro módulos y usada en uno, y las otras tres
copias pasaban el corte porque la palabra existía en Settings. Al unificar el
formulario-de-panel aparecieron así media docena de restos.

Ahora se resuelve a qué módulo apunta cada `styles` de cada fichero, siguiendo
los dos saltos que hay en esta base: el import directo y la re-exportación
(`export { default as settingsStyles } from './Settings.module.css'`, que usan
las nueve sub-pestañas de Settings). Lo que no se pueda resolver no se juzga.

    node dev/css-muertas.mjs
*/
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'

const RAIZ = join(import.meta.dirname, '..', 'DnsServerCore', 'webapp', 'src')

function ficheros(dir, filtro, acc = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) ficheros(p, filtro, acc)
    else if (filtro.test(e)) acc.push(p)
  }
  return acc
}

const modulos = ficheros(RAIZ, /\.module\.css$/)
const fuentes = ficheros(RAIZ, /\.tsx?$/).filter((f) => !/\.test\./.test(f))
const codigo = new Map(fuentes.map((f) => [f, readFileSync(f, 'utf8')]))

/** Resuelve un import relativo a un fichero real de `src/`. */
function resolver(desde, rel) {
  const base = resolve(dirname(desde), rel)
  for (const cand of [base, `${base}.tsx`, `${base}.ts`, join(base, 'index.tsx')]) {
    if (existsSync(cand) && statSync(cand).isFile()) return cand
  }
  return null
}

/*
Paso 1: qué módulo trae cada fichero con nombre propio, y bajo qué nombre lo
vuelve a exportar. `alias` es lo que ese fichero escribe; `expone` es el nombre
por el que otro fichero puede pedírselo.
*/
const alias = new Map() // fichero -> Map(identificador -> módulo)
const expone = new Map() // fichero -> Map(nombre exportado -> módulo)
for (const [f, src] of codigo) {
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
  expone.set(f, e)
}

/* Paso 2: el salto indirecto — `import { settingsStyles as styles } from '../parts'`. */
for (const [f, src] of codigo) {
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"](\.[^'"]*)['"]/g)) {
    const destino = resolver(f, m[2])
    if (!destino || !expone.has(destino)) continue
    for (const trozo of m[1].split(',')) {
      const [, nombre, local] = /^\s*(\w+)(?:\s+as\s+(\w+))?\s*$/.exec(trozo.trim()) ?? []
      if (nombre && expone.get(destino).has(nombre)) {
        alias.get(f).set(local ?? nombre, expone.get(destino).get(nombre))
      }
    }
  }
}

/*
Un módulo consumido con corchetes —`styles[variant]`— puede usar cualquier
clase, así que no se juzga. Hay que mirar el identificador con el que CADA
fichero importa su módulo: el Dashboard llama `s` a un objeto de datos y hace
`s[m.k]`, que no tiene nada que ver con sus estilos.
*/
const dinamicos = new Set()
for (const [f, src] of codigo) {
  for (const [id, mod] of alias.get(f)) {
    if (new RegExp(`\\b${id}\\[`).test(src)) dinamicos.add(mod)
  }
}

/* Paso 3: qué clases nombra cada módulo, ya atribuidas. */
const nombradas = new Map(modulos.map((m) => [m, new Set()]))
const consumidores = new Map(modulos.map((m) => [m, new Set()]))
for (const [f, src] of codigo) {
  for (const [id, mod] of alias.get(f)) {
    if (!nombradas.has(mod)) continue
    consumidores.get(mod).add(f)
    for (const m of src.matchAll(new RegExp(`\\b${id}\\.(\\w+)`, 'g'))) {
      nombradas.get(mod).add(m[1])
    }
  }
}

/*
Cuatro sitios de un CSS parecen declarar una clase y no declaran ninguna: los
comentarios (`.zt` vivía en uno), el contenido de `url()` —donde `www.w3.org` se
lee como `.w3`—, los `:global()` y la ruta de un `composes: … from '…'`, que
acaba en `.module.css` y se leería como dos clases, `.module` y `.css`. Se
recortan antes de mirar.
*/
const limpiar = (css) =>
  css
    .replaceAll(/\/\*[\s\S]*?\*\//g, '')
    .replaceAll(/url\((?:[^()]|\([^()]*\))*\)/g, '')
    .replaceAll(/:global\([^)]*\)/g, '')
    .replaceAll(/(['"])(?:(?!\1).)*\1/g, "''")

/* Y una clase también vive si otro módulo la hereda con `composes: x from '…'`. */
const compuestas = new Map(modulos.map((m) => [m, new Set()]))
for (const mod of modulos) {
  // Sin `limpiar`: ahí se borran las cadenas, y la ruta del `from` es una.
  const css = readFileSync(mod, 'utf8').replaceAll(/\/\*[\s\S]*?\*\//g, '')
  for (const m of css.matchAll(/composes:\s*([\w\s-]+?)\s+from\s*['"]([^'"]+)['"]/g)) {
    const destino = resolve(dirname(mod), m[2])
    if (!compuestas.has(destino)) continue
    for (const c of m[1].trim().split(/\s+/)) compuestas.get(destino).add(c)
  }
}

let muertas = 0
let total = 0
const dudosos = new Set()

for (const mod of modulos) {
  const css = readFileSync(mod, 'utf8')
  const declaradas = new Set()
  for (const m of limpiar(css).matchAll(/\.(-?[A-Za-z_][\w-]*)/g)) declaradas.add(m[1])
  total += declaradas.size

  if (dinamicos.has(mod)) {
    dudosos.add(`${mod.slice(RAIZ.length + 1)} (acceso por corchetes: no se juzga)`)
    continue
  }
  if (consumidores.get(mod).size === 0 && compuestas.get(mod).size === 0) {
    dudosos.add(`${mod.slice(RAIZ.length + 1)} (sin consumidor resuelto: no se juzga)`)
    continue
  }

  const vivas = new Set([...nombradas.get(mod), ...compuestas.get(mod)])
  const sinUsar = [...declaradas].filter((c) => !vivas.has(c))

  if (sinUsar.length) {
    muertas += sinUsar.length
    console.log(`\n${mod.slice(RAIZ.length + 1)}  —  ${consumidores.get(mod).size} consumidor(es)`)
    for (const c of sinUsar) {
      const linea = css.split('\n').findIndex((l) => l.includes(`.${c}`)) + 1
      console.log(`  .${c}  (línea ${linea})`)
    }
  }
}

console.log(`\n${muertas} clases declaradas y nunca nombradas, de ${total} en ${modulos.length} módulos`)
if (dudosos.size) {
  console.log('\nNo juzgados:')
  for (const d of dudosos) console.log(`  ${d}`)
}
