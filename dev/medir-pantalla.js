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
      if (w < 24 || h < 24) out.tactil.push(`${el.tagName} ${w}×${h}  ${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 24)}`)
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
  for (const t of document.querySelectorAll('[role="tab"]')) {
    t.click(); await espera(ms)
    todo[t.textContent.trim().replace(/[^\w ]/g, '')] = medir()
  }
  return todo
}
