/*
Reglas CSS escritas y nunca aplicadas.

Este es el defecto que ninguna prueba ve y ninguna captura delata: una clase
declarada en un módulo que ningún componente referencia. Pasó con `.v`, `.p` y
`.k` de los tiles del Dashboard, que llevaban desde la fase 1 sin aplicarse.

Es estático a propósito. Barrer el DOM daría falsos positivos con todo lo que
vive en un estado al que la sesión no llegó (un diálogo cerrado, una tabla
vacía, un hover). Aquí una clase sólo se declara muerta si NINGÚN fichero de
`src/` la nombra.

    node dev/css-muertas.mjs
*/
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, basename } from 'node:path'

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

/*
Un módulo consumido con corchetes —`styles[variant]`— puede usar cualquier
clase, así que no se juzga. Hay que mirar el identificador con el que CADA
fichero importa su módulo: el Dashboard llama `s` a un objeto de datos y hace
`s[m.k]`, que no tiene nada que ver con sus estilos. Buscar `s[` a secas lo
declaraba dinámico y le perdonaba las clases muertas — justo la pantalla donde
apareció el defecto original.
*/
const dinamicos = new Set()
for (const [f, src] of codigo) {
  for (const m of src.matchAll(/import\s+(\w+)\s+from\s+['"][^'"]*\.module\.css['"]/g)) {
    if (new RegExp(`\\b${m[1]}\\[`).test(src)) dinamicos.add(f)
  }
}

let muertas = 0
let total = 0
const dudosos = new Set()
const tsx = [...codigo.values()].join('\n')
const todosLosCss = ficheros(RAIZ, /\.css$/)
  .map((f) => readFileSync(f, 'utf8'))
  .join('\n')

/*
Tres sitios de un CSS parecen declarar una clase y no declaran ninguna, y los
tres dieron falso positivo en la primera versión: los comentarios (`.zt` vivía
en uno), el contenido de `url()` —donde `www.w3.org` se lee como `.w3`— y los
`:global()`. Se recortan antes de mirar.
*/
const limpiar = (css) =>
  css
    .replaceAll(/\/\*[\s\S]*?\*\//g, '')
    .replaceAll(/url\((?:[^()]|\([^()]*\))*\)/g, '')
    .replaceAll(/:global\([^)]*\)/g, '')

for (const mod of modulos) {
  const css = readFileSync(mod, 'utf8')
  const declaradas = new Set()
  for (const m of limpiar(css).matchAll(/\.(-?[A-Za-z_][\w-]*)/g)) declaradas.add(m[1])
  total += declaradas.size

  // Un módulo puede llegar a su pantalla re-exportado desde un tercero
  // (`export { styles as adminStyles }` en partes.tsx, que usan ocho pantallas).
  // Seguir el grafo de imports es frágil; buscar el nombre en TODO `src/` no lo
  // es, y su único error posible es callar una clase muerta —nunca inventarla—.
  const importadores = [...codigo].filter(([, src]) => src.includes(basename(mod)))
  if (importadores.some(([f]) => dinamicos.has(f))) {
    dudosos.add(`${mod.slice(RAIZ.length + 1)} (acceso por corchetes: no se juzga)`)
    continue
  }

  const sinUsar = [...declaradas].filter((c) => {
    const id = c.replaceAll('-', '\\-')
    // nombrada desde un componente…
    if (new RegExp(`[.\\['"\`]${id}\\b`).test(tsx)) return false
    // …o heredada por otro módulo con `composes: golpe from '…'`
    return !new RegExp(`composes:[^;]*\\b${id}\\b[^;]*from`).test(todosLosCss)
  })
  const usan = importadores

  if (sinUsar.length) {
    muertas += sinUsar.length
    console.log(`\n${mod.slice(RAIZ.length + 1)}  —  ${usan.length} consumidor(es)`)
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
