/*
¿Se nos ha caído algún destino de upstream?

El plan de revisión decía «abrir la misma pantalla en `technitium-ui-ref` y
comparar a ojo». A ojo se pasan cosas — se pasaron, y de las gordas: el panel
About se había quedado con ocho de sus nueve enlaces fuera y el pie del `body`
entero, con el correo de soporte y el de donaciones del autor dentro.

Esto lo hace por lista, y sin navegador: la consola de upstream es un único
`index.html` con TODOS sus paneles en el marcado, así que sus destinos se leen
del HTML; los nuestros se leen del código de la aplicación. Sin dependencias
nuevas —meter Playwright en `package.json` aparecería en el diff del pull
request— y por tanto ejecutable en cualquier sitio con la consola de referencia
levantada.

    node dev/check-paridad-controles.mjs
    REF=http://otra:5381 node dev/check-paridad-controles.mjs

Lo que NO contesta: si un destino que está en las dos apunta a lo mismo desde la
pantalla equivalente, ni si un botón que existe en las dos hace lo mismo. Para
la conducta está `check-paridad-acciones.sh`, que compara el estado del
servidor.
*/
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const REF = process.env.REF ?? 'http://127.0.0.1:5381'
const FUENTE = new URL('../DnsServerCore/webapp/src/', import.meta.url).pathname

/* Destinos que upstream tiene y aquí NO deben estar, con su razón. Cada línea
   es una decisión, no un olvido: si no está justificada, es un hallazgo. */
const EXCUSAS = new Map([
  // El modal de temas desaparece con la decisión «un solo tema, el oscuro».
  // No lleva enlaces propios, así que hoy esta lista está vacía a propósito:
  // se deja escrita para que quien añada una excusa tenga que razonarla aquí.
])

function ficheros(dir) {
  const out = []
  for (const n of readdirSync(dir)) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) out.push(...ficheros(p))
    else if (/\.(tsx?|css)$/.test(n)) out.push(p)
  }
  return out
}

const normaliza = (u) => u.replace(/\/$/, '').replace(/^http:/, 'https:')

const nuestro = ficheros(FUENTE)
  .filter((f) => !/\.test\./.test(f))
  .map((f) => readFileSync(f, 'utf8'))
  .join('\n')

const html = await fetch(`${REF}/`).then((r) => {
  if (!r.ok) throw new Error(`la consola de referencia responde ${r.status} en ${REF}`)
  return r.text()
})

/* Los destinos de upstream, con la pantalla en la que aparecen. */
const suyos = new Map()
for (const m of html.matchAll(/href="((?:https?:|mailto:)[^"]+)"/g)) {
  const url = normaliza(m[1])
  if (!suyos.has(url)) suyos.set(url, [])
  /* El contenedor con id más cercano hacia atrás. Es una PISTA, no una
     verdad: el marcado de upstream no cierra los modales antes del siguiente,
     así que sirve para ir a buscarlo, no para citarlo. */
  const antes = html.slice(0, m.index)
  const cerca = [...antes.matchAll(/id="(modal\w+|\w*TabPane\w+|footer)"/g)].pop()
  suyos.get(url).push(cerca ? cerca[1] : '?')
}

const faltan = []
for (const [url] of suyos) {
  if (EXCUSAS.has(url)) continue
  // se busca el destino tal cual y sin la barra final: en el código puede ir
  // partido por el formateador, pero la URL nunca se parte.
  const crudo = url.replace(/^https:/, 'http:')
  if (nuestro.includes(url) || nuestro.includes(crudo) || nuestro.includes(`${url}/`)) continue
  faltan.push(url)
}

const total = suyos.size
for (const url of faltan) {
  console.log(`  FALTA    ${url}   (upstream, cerca de: ${[...new Set(suyos.get(url))].join(', ')})`)
}

console.log(
  faltan.length === 0
    ? `\nPARIDAD DE DESTINOS: los ${total} de upstream están en la consola nueva.`
    : `\nPARIDAD DE DESTINOS: faltan ${faltan.length} de ${total}.`,
)
process.exit(faltan.length === 0 ? 0 : 1)
