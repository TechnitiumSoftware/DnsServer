/*
Lo mismo, escrito en dos módulos.

`css-muertas.mjs` contesta si una regla sobra. Ésta contesta algo distinto: si la
MISMA regla está escrita más de una vez. Es el defecto que produce la deriva —dos
copias que empiezan iguales y dejan de serlo—, y ninguna revisión pantalla a
pantalla lo ve, porque en cada pantalla, por separado, todo parece correcto.

Medido antes de arreglarlo, encontró 27 grupos, y de ahí salieron entre otras:

  · once `<textarea>` que se pintaban la caja a mano, con radio 6 en vez de 8 y
    sin la sombra interior que llevan todos los demás campos;
  · el `<code>` en línea en cinco módulos y el párrafo de entrada en cinco, con
    uno a 1,65 de interlínea contra 1,6 de los otros cuatro;
  · el chevron del `<details>` recodificado a mano como SVG en un `data:` URI,
    en dos módulos, con otro grosor de trazo que el resto de los iconos;
  · el recuento del pie de una tabla con cuatro distancias distintas.

    node dev/css-repetido.mjs

## Cómo leerlo

Agrupa por CUERPO de la regla, ignorando `composes`, y sólo enseña los cuerpos
que aparecen en más de un módulo. Eso deja fuera lo que ya está compartido —una
clase que compone de otra no repite nada— y deja dentro tres cosas que NO son
defectos, así que hay que mirarlas antes de tocar:

  · **Aplicar el mismo token.** Dos componentes con `background: var(--acc)` no
    duplican nada: el token ES la fuente única, y `composes` ni siquiera alcanza
    a una pseudo-clase o a un selector de atributo, que es de donde salen casi
    todos estos. Ejemplo real: el resaltado de la opción de un menú y el de la
    opción de un desplegable.
  · **Coincidencias de maquetación genérica.** `display:flex;
    flex-direction:column; gap:var(--s-9)` sale en una columna de About, otra
    del Dashboard y el formulario de Login. No son la misma cosa; es que hay
    pocas maneras de apilar tres elementos.
  · **El mismo colapso responsivo.** `grid-template-columns: minmax(0,1fr)`
    dentro de una media query es «a una columna en estrecho», y eso lo dicen
    todas las rejillas de la consola.

El umbral de longitud del cuerpo está para no ahogar la salida en reglas de una
sola propiedad, que casi siempre son de los tres casos de arriba.
*/
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const RAIZ = join(import.meta.dirname, '..', 'DnsServerCore', 'webapp', 'src')
const MINIMO = Number(process.env.MINIMO ?? 28)

function ficheros(dir, acc = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) ficheros(p, acc)
    else if (e.endsWith('.module.css')) acc.push(p)
  }
  return acc
}

const grupos = new Map()

for (const mod of ficheros(RAIZ)) {
  const css = readFileSync(mod, 'utf8').replaceAll(/\/\*[\s\S]*?\*\//g, '')
  for (const m of css.matchAll(/([^{}]+)\{([^{}]+)\}/g)) {
    const selector = m[1].trim().split('\n').at(-1).trim()
    /* Normalizado: sin espacios y en orden, para que dos reglas iguales escritas
       con distinto formato —o con las propiedades en otro orden— coincidan. */
    const cuerpo = m[2]
      .split(';')
      .map((d) => d.trim().replaceAll(' ', ''))
      .filter((d) => d && !d.startsWith('composes'))
      .sort()
      .join(' ')
    if (cuerpo.length < MINIMO) continue
    if (!grupos.has(cuerpo)) grupos.set(cuerpo, [])
    grupos.get(cuerpo).push({ mod: mod.slice(RAIZ.length + 1), selector })
  }
}

const repetidos = [...grupos]
  .filter(([, sitios]) => new Set(sitios.map((s) => s.mod)).size > 1)
  .sort((a, b) => b[1].length - a[1].length)

for (const [cuerpo, sitios] of repetidos) {
  console.log(`\n[${sitios.length}] ${cuerpo}`)
  for (const s of sitios) console.log(`     ${s.mod}  ${s.selector}`)
}

console.log(`\n${repetidos.length} cuerpos de regla escritos en más de un módulo`)
