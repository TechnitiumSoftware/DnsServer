/*
Las mediciones de la revisión pantalla a pantalla, en un solo sitio.

Se pega en la consola del navegador —o se pasa a `browser_evaluate`— y devuelve
todo lo que un número puede contestar de la pantalla que esté abierta. Está aquí
y no en el bundle a propósito: es herramienta de revisión, no de la consola.

    medir()            la pantalla actual
    await recorrer()   las doce secciones, una tras otra

Lo que NO contesta esto es si la pantalla se entiende, si el dato domina sobre
los controles y si el estado vacío dice qué hacer. Para eso, la captura.
*/

const ESCALA = new Set([0, 2, 4, 6, 7, 8, 9, 10, 12, 14, 16, 24, 32])

const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
const lum = (s) => { const m = s.match(/[\d.]+/g); return m ? 0.2126*lin(+m[0]) + 0.7152*lin(+m[1]) + 0.0722*lin(+m[2]) : null }
const ratio = (a, b) => { const hi = Math.max(a, b), lo = Math.min(a, b); return (hi + 0.05) / (lo + 0.05) }

/*
Un color declarado en una regla casi nunca es `rgb(...)`: es `var(--hover)`, un
hexadecimal o un nombre. Se normaliza dejando que lo haga el navegador —un nodo
suelto al que se le asigna el valor— y resolviendo antes las variables contra el
elemento, que es quien sabe cuánto vale `--hover` en su rama del árbol.

Esto no es un detalle: la primera versión del barrido sólo entendía `rgb()`, y de
33 reglas de hover y foco medía 3. Devolvía lista vacía y parecía un aprobado.
*/
const normalizador = document.createElement('span')
function resolverColor(valor, el) {
  let v = valor
  for (let i = 0; i < 4 && v.includes('var('); i++) {
    v = v.replace(/var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*))?\)/g, (_, nombre, porDefecto) => {
      const leido = getComputedStyle(el).getPropertyValue(nombre).trim()
      return leido || (porDefecto ?? '').trim()
    })
  }
  // Una variable puede valer un shorthand entero: `--focus` es `2px solid #f5a524`,
  // no un color. Sin recortar el trozo de color, lum() parsea el `2px` y devuelve
  // una luminancia inventada — y con ella un contraste que no significa nada.
  const soloColor = v.match(/#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b[a-z]+\b(?=\s*$)/i)
  if (soloColor) v = soloColor[0]
  normalizador.style.color = ''
  normalizador.style.color = v
  if (!normalizador.style.color) return v
  document.body.appendChild(normalizador)
  const rgb = getComputedStyle(normalizador).color
  normalizador.remove()
  return rgb
}

/** El fondo que se ve de verdad, subiendo hasta el primer opaco. */
function fondoReal(el) {
  for (let e = el; e; e = e.parentElement) {
    const m = getComputedStyle(e).backgroundColor.match(/[\d.]+/g)
    if (m && (m.length < 4 || +m[3] > 0.95)) return getComputedStyle(e).backgroundColor
  }
  return getComputedStyle(document.body).backgroundColor
}

/** El área sensible real, contando el pseudo-elemento que la amplíe. */
function areaSensible(el) {
  const r = el.getBoundingClientRect()
  let { width: w, height: h } = r
  const a = getComputedStyle(el, '::after')
  if (a.content !== 'none' && a.position === 'absolute') {
    for (const [lado, eje] of [['top','h'],['bottom','h'],['left','w'],['right','w']]) {
      const v = parseFloat(a[lado]) || 0
      if (v < 0) { if (eje === 'h') h += -v; else w += -v }
    }
  }
  const lab = el.tagName === 'INPUT' ? el.closest('label') : null
  if (lab) { const lr = lab.getBoundingClientRect(); w = Math.max(w, lr.width); h = Math.max(h, lr.height) }
  return { w: Math.round(w), h: Math.round(h) }
}

/*
Un enlace DENTRO de una frase no incumple el mínimo de 24 px, y no es una manga
ancha: WCAG 2.2 lo exime literalmente —«Inline: the target is in a sentence or
its size is otherwise constrained by the line-height of non-target text»—. Y con
razón: ampliarle el área sensible le haría tapar las palabras de al lado.

Sin esta excepción el barrido levantaba quince enlaces de ayuda de 12 px como si
fueran defectos, y el arreglo habría sido peor que el problema.
*/
function enLinea(el) {
  if (el.tagName !== 'A' || getComputedStyle(el).display !== 'inline') return false
  const p = el.parentElement
  if (!p) return false
  const textoAlrededor = [...p.childNodes]
    .filter((n) => n !== el)
    .map((n) => n.textContent.trim())
    .join('')
  return textoAlrededor.length > 0
}

function medir(raiz = document.querySelector('main') || document.body) {
  const out = { contraste: [], espaciado: [], tactil: [], sinNombre: [], desborde: null, ritmo: [] }
  const vistos = new Set()

  for (const el of raiz.querySelectorAll('*')) {
    const r = el.getBoundingClientRect()
    if (!r.width || !r.height) continue
    const c = getComputedStyle(el)

    // 1. contraste del texto propio
    if ([...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 1)) {
      const lt = lum(c.color), lf = lum(fondoReal(el))
      if (lt != null && lf != null) {
        const cr = ratio(lt, lf), tam = parseFloat(c.fontSize)
        const min = (tam >= 18.66 || (tam >= 14 && +c.fontWeight >= 700)) ? 3 : 4.5
        if (cr < min) out.contraste.push({ cr: +cr.toFixed(2), min, texto: el.textContent.trim().slice(0, 40) })
      }
    }

    // 2. espaciado fuera de la escala
    for (const p of ['paddingTop','paddingRight','paddingBottom','paddingLeft',
                     'marginTop','marginRight','marginBottom','marginLeft','rowGap','columnGap']) {
      const n = Math.round(parseFloat(c[p]) * 100) / 100
      if (!c[p].endsWith('px') || !n || ESCALA.has(n)) continue
      const k = `${n}px ${p} ${el.tagName}.${(typeof el.className === 'string' ? el.className : '').split(' ')[0]}`
      if (!vistos.has(k)) { vistos.add(k); out.espaciado.push(k) }
    }

    // 3. controles: tamaño y nombre
    if (['BUTTON','A','INPUT','SELECT','TEXTAREA'].includes(el.tagName)) {
      const { w, h } = areaSensible(el)
      if ((w < 24 || h < 24) && !enLinea(el)) out.tactil.push(`${el.tagName} ${w}×${h}  ${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 24)}`)
      if (['BUTTON','A'].includes(el.tagName)) {
        const nombre = (el.getAttribute('aria-label') || el.textContent || '').trim()
        const etiquetado = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)
        if (!nombre && !etiquetado) out.sinNombre.push(el.outerHTML.slice(0, 90))
      }
    }
  }

  // 4. desborde horizontal
  const d = document.documentElement
  out.desborde = d.scrollWidth > d.clientWidth ? `${d.scrollWidth} > ${d.clientWidth}` : null

  // 5. ritmo vertical entre bloques de primer nivel
  const hijos = [...raiz.children].filter(e => e.getBoundingClientRect().height > 0)
  for (let i = 1; i < hijos.length; i++) {
    out.ritmo.push(Math.round(hijos[i].getBoundingClientRect().top - hijos[i - 1].getBoundingClientRect().bottom))
  }
  return out
}

/** El contraste de un estado contra su reposo. Se le pasa el elemento apuntado. */
function medirEstado(el, fondoReposo) {
  return +ratio(lum(fondoReal(el)), lum(fondoReposo)).toFixed(3)
}

async function recorrer(ms = 650) {
  const espera = (t) => new Promise(r => setTimeout(r, t))
  const todo = {}
  for (const t of document.querySelectorAll('nav[aria-label="Sections"] a')) {
    t.click(); await espera(ms)
    todo[t.textContent.trim().replace(/[^\w ]/g, '')] = medir()
  }
  return todo
}

/*
El barrido de estados: hover y foco de TODA la pantalla, no control a control.

`medirEstado` obliga a apuntar un elemento y saberse su reposo de memoria, así
que en la práctica se mide un botón y se dan por buenos los otros cuarenta. Esto
lo hace al revés: lee las reglas `:hover` y `:focus-visible` de las hojas de
estilo, busca a quién le tocan en esta pantalla, y compara el color que la regla
declara contra el fondo real que ese elemento tiene AHORA, en reposo.

Por debajo de 1.20:1 el ojo no separa dos planos. Así salió el `--hover` que era
un color fijo y daba 1.11:1 sobre el escalón elevado.

    barridoEstados()
*/
/*
De qué color se pinta un estado, según lo que la regla haya escrito.

Con `background-color: var(--hover)` basta leer la longhand. Con la forma
abreviada `background: var(--hover)` NO: el navegador guarda el shorthand como
«sustitución pendiente» y devuelve cadena vacía en todas sus longhands. De 33
reglas de hover y foco, eso dejaba fuera a 22 — las que más importan, porque
escribir la abreviada es lo natural.
*/
function coloresDeLaRegla(estilo) {
  const salida = []
  for (const prop of ['background-color', 'background', 'border-color', 'border',
                      'outline-color', 'outline', 'box-shadow']) {
    const v = estilo.getPropertyValue(prop).trim()
    if (!v || v === 'transparent' || v === 'inherit' || v === 'none') continue
    const m = v.match(/var\([^()]*(?:\([^()]*\)[^()]*)*\)|#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)/i)
    if (m) salida.push({ color: m[0], prop })
    else if (prop.endsWith('-color')) salida.push({ color: v, prop })
  }
  return salida
}

function barridoEstados(raiz = document.body, minimo = 1.2) {
  const flojos = []
  const vistos = new Set()
  let reglas = 0, pares = 0

  for (const hoja of document.styleSheets) {
    let cssReglas
    try { cssReglas = hoja.cssRules } catch { continue }  // hoja de otro origen
    for (const regla of cssReglas) {
      if (!regla.selectorText || !/:(hover|focus-visible)\b/.test(regla.selectorText)) continue

      const decls = coloresDeLaRegla(regla.style)
      if (!decls.length) continue
      reglas++
      // Un `outline` con offset y una `box-shadow` se pintan FUERA de la caja:
      // se ven contra el fondo del padre, no contra el del propio elemento.
      // Compararlos contra el elemento daba 1.00:1 en la pestaña seleccionada
      // —anillo ámbar sobre botón ámbar— y ahí no hay defecto ninguno: el anillo
      // cae sobre la barra lateral, que es oscura.


      for (const sel of regla.selectorText.split(',')) {
        const base = sel.replace(/:(hover|focus-visible)\b/g, '').trim()
        if (!base) continue
        let elementos
        try { elementos = raiz.querySelectorAll(base) } catch { continue }
        for (const el of elementos) {
          const r = el.getBoundingClientRect()
          if (!r.width || !r.height) continue
          /* Una regla de hover suele cambiar VARIAS cosas a la vez: la casilla
             marcada tiñe un `border-color` que ya valía lo mismo y a la vez
             añade un anillo de `box-shadow` que sí se ve. Quedarse con la
             primera propiedad daba 1.00:1 y un defecto que no existe. Se mide
             cada canal y manda el que MÁS cambia: si uno solo se percibe, el
             estado se percibe. */
          let mejor = null
          for (const decl of decls) {
            const declarado = resolverColor(decl.color, el)
            const ld = lum(declarado)
            if (ld == null) continue
            const fuera = decl.prop.startsWith('outline') || decl.prop === 'box-shadow'
            const reposo = fondoReal(fuera ? (el.parentElement ?? el) : el)
            const cr = +ratio(ld, lum(reposo)).toFixed(3)
            if (mejor == null || cr > mejor.cr) mejor = { cr, decl, declarado, reposo }
          }
          if (mejor == null) continue
          pares++
          const { cr, decl, declarado, reposo } = mejor
          if (cr >= minimo) continue
          const k = `${sel}|${cr}`
          if (vistos.has(k)) continue
          vistos.add(k)
          flojos.push({
            cr,
            estado: /focus-visible/.test(sel) ? 'foco' : 'hover',
            selector: sel.trim().slice(0, 60),
            declarado: `${decl.prop}: ${decl.color} = ${declarado}`,
            reposo,
            ejemplo: (el.textContent || el.tagName).trim().slice(0, 30),
          })
        }
      }
    }
  }
  // El recuento va en la respuesta a propósito: un barrido que no mide ningún
  // par también devuelve [], y eso no es un aprobado, es una herramienta muerta.
  return { reglas, pares, flojos: flojos.sort((a, b) => a.cr - b.cr) }
}
