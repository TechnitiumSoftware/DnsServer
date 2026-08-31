/*
The measurements for the screen-by-screen review, all in one place.

Paste it into the browser console —or pass it to `browser_evaluate`— and it
returns everything a number can answer about whichever screen is open. It lives
here and not in the bundle on purpose: it is a review tool, not part of the
console.

    medir()            the current screen
    await recorrer()   the twelve sections, one after another

What this does NOT answer is whether the screen makes sense, whether the data
dominates over the controls, and whether the empty state says what to do. For
that, the screenshot.
*/

const SCALE = new Set([0, 2, 4, 6, 7, 8, 9, 10, 12, 14, 16, 24, 32])

const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
const lum = (s) => { const m = s.match(/[\d.]+/g); return m ? 0.2126*lin(+m[0]) + 0.7152*lin(+m[1]) + 0.0722*lin(+m[2]) : null }
const ratio = (a, b) => { const hi = Math.max(a, b), lo = Math.min(a, b); return (hi + 0.05) / (lo + 0.05) }

/*
A colour declared in a rule is almost never `rgb(...)`: it is `var(--hover)`, a
hex value or a name. It is normalised by letting the browser do it —a detached
node the value is assigned to— resolving the variables first against the element,
which is the one that knows what `--hover` is worth in its branch of the tree.

This is not a detail: the first version of the sweep only understood `rgb()`, and
out of 33 hover and focus rules it measured 3. It returned an empty list and
looked like a pass.
*/
const normaliser = document.createElement('span')
function resolveColour(value, el) {
  let v = value
  for (let i = 0; i < 4 && v.includes('var('); i++) {
    v = v.replace(/var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*))?\)/g, (_, name, fallback) => {
      const read = getComputedStyle(el).getPropertyValue(name).trim()
      return read || (fallback ?? '').trim()
    })
  }
  // A variable can be worth a whole shorthand: `--focus` is `2px solid #f5a524`,
  // not a colour. Without cutting out the colour part, lum() parses the `2px` and
  // returns an invented luminance — and with it a contrast that means nothing.
  const colourOnly = v.match(/#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b[a-z]+\b(?=\s*$)/i)
  if (colourOnly) v = colourOnly[0]
  normaliser.style.color = ''
  normaliser.style.color = v
  if (!normaliser.style.color) return v
  document.body.appendChild(normaliser)
  const rgb = getComputedStyle(normaliser).color
  normaliser.remove()
  return rgb
}

/** The background actually seen, walking up to the first opaque one. */
function realBackground(el) {
  for (let e = el; e; e = e.parentElement) {
    const m = getComputedStyle(e).backgroundColor.match(/[\d.]+/g)
    if (m && (m.length < 4 || +m[3] > 0.95)) return getComputedStyle(e).backgroundColor
  }
  return getComputedStyle(document.body).backgroundColor
}

/** The real hit area, counting any pseudo-element that enlarges it. */
function hitArea(el) {
  const r = el.getBoundingClientRect()
  let { width: w, height: h } = r
  const a = getComputedStyle(el, '::after')
  if (a.content !== 'none' && a.position === 'absolute') {
    for (const [side, axis] of [['top','h'],['bottom','h'],['left','w'],['right','w']]) {
      const v = parseFloat(a[side]) || 0
      if (v < 0) { if (axis === 'h') h += -v; else w += -v }
    }
  }
  const lab = el.tagName === 'INPUT' ? el.closest('label') : null
  if (lab) { const lr = lab.getBoundingClientRect(); w = Math.max(w, lr.width); h = Math.max(h, lr.height) }
  return { w: Math.round(w), h: Math.round(h) }
}

/*
A link INSIDE a sentence does not breach the 24 px minimum, and this is not
leniency: WCAG 2.2 exempts it literally —«Inline: the target is in a sentence or
its size is otherwise constrained by the line-height of non-target text»—. And
rightly so: enlarging its hit area would make it cover the words next to it.

Without this exception the sweep raised fifteen 12 px help links as if they were
defects, and the fix would have been worse than the problem.
*/
function isInline(el) {
  if (el.tagName !== 'A' || getComputedStyle(el).display !== 'inline') return false
  const p = el.parentElement
  if (!p) return false
  const surroundingText = [...p.childNodes]
    .filter((n) => n !== el)
    .map((n) => n.textContent.trim())
    .join('')
  return surroundingText.length > 0
}

function medir(root = document.querySelector('main') || document.body) {
  const out = { contraste: [], espaciado: [], tactil: [], sinNombre: [], desborde: null, ritmo: [] }
  const seen = new Set()

  for (const el of root.querySelectorAll('*')) {
    const r = el.getBoundingClientRect()
    if (!r.width || !r.height) continue
    const c = getComputedStyle(el)

    // 1. contrast of its own text
    if ([...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 1)) {
      const lt = lum(c.color), lf = lum(realBackground(el))
      if (lt != null && lf != null) {
        const cr = ratio(lt, lf), size = parseFloat(c.fontSize)
        const min = (size >= 18.66 || (size >= 14 && +c.fontWeight >= 700)) ? 3 : 4.5
        if (cr < min) out.contraste.push({ cr: +cr.toFixed(2), min, texto: el.textContent.trim().slice(0, 40) })
      }
    }

    // 2. spacing outside the scale
    for (const p of ['paddingTop','paddingRight','paddingBottom','paddingLeft',
                     'marginTop','marginRight','marginBottom','marginLeft','rowGap','columnGap']) {
      const n = Math.round(parseFloat(c[p]) * 100) / 100
      if (!c[p].endsWith('px') || !n || SCALE.has(n)) continue
      const k = `${n}px ${p} ${el.tagName}.${(typeof el.className === 'string' ? el.className : '').split(' ')[0]}`
      if (!seen.has(k)) { seen.add(k); out.espaciado.push(k) }
    }

    // 3. controls: size and name
    if (['BUTTON','A','INPUT','SELECT','TEXTAREA'].includes(el.tagName)) {
      const { w, h } = hitArea(el)
      if ((w < 24 || h < 24) && !isInline(el)) out.tactil.push(`${el.tagName} ${w}×${h}  ${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 24)}`)
      if (['BUTTON','A'].includes(el.tagName)) {
        const name = (el.getAttribute('aria-label') || el.textContent || '').trim()
        const labelled = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)
        if (!name && !labelled) out.sinNombre.push(el.outerHTML.slice(0, 90))
      }
    }
  }

  // 4. horizontal overflow
  const d = document.documentElement
  out.desborde = d.scrollWidth > d.clientWidth ? `${d.scrollWidth} > ${d.clientWidth}` : null

  // 5. vertical rhythm between top-level blocks
  const children = [...root.children].filter(e => e.getBoundingClientRect().height > 0)
  for (let i = 1; i < children.length; i++) {
    out.ritmo.push(Math.round(children[i].getBoundingClientRect().top - children[i - 1].getBoundingClientRect().bottom))
  }
  return out
}

/** The contrast of a state against its resting look. Pass it the element being pointed at. */
function medirEstado(el, restingBackground) {
  return +ratio(lum(realBackground(el)), lum(restingBackground)).toFixed(3)
}

async function recorrer(ms = 650) {
  const wait = (t) => new Promise(r => setTimeout(r, t))
  const all = {}
  for (const t of document.querySelectorAll('nav[aria-label="Sections"] a')) {
    t.click(); await wait(ms)
    all[t.textContent.trim().replace(/[^\w ]/g, '')] = medir()
  }
  return all
}

/*
The state sweep: hover and focus across the WHOLE screen, not control by control.

`medirEstado` forces you to point at an element and know its resting look from
memory, so in practice you measure one button and take the other forty on faith.
This does it the other way round: it reads the `:hover` and `:focus-visible` rules
from the stylesheets, finds who they apply to on this screen, and compares the
colour the rule declares against the real background that element has NOW, at
rest.

Below 1.20:1 the eye does not separate two planes. That is how the `--hover` that
was a fixed colour and gave 1.11:1 over the raised step came out.

    barridoEstados()
*/
/*
What colour a state is painted, according to what the rule wrote.

With `background-color: var(--hover)` reading the longhand is enough. With the
shorthand `background: var(--hover)` it is NOT: the browser stores the shorthand
as a "pending substitution" and returns an empty string for all its longhands.
Out of 33 hover and focus rules, that left 22 out — the ones that matter most,
because writing the shorthand is the natural thing to do.
*/
function ruleColours(style) {
  const out = []
  for (const prop of ['background-color', 'background', 'border-color', 'border',
                      'outline-color', 'outline', 'box-shadow']) {
    const v = style.getPropertyValue(prop).trim()
    if (!v || v === 'transparent' || v === 'inherit' || v === 'none') continue
    const m = v.match(/var\([^()]*(?:\([^()]*\)[^()]*)*\)|#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)/i)
    if (m) out.push({ color: m[0], prop })
    else if (prop.endsWith('-color')) out.push({ color: v, prop })
  }
  return out
}

function barridoEstados(root = document.body, minimum = 1.2) {
  const weak = []
  const seen = new Set()
  let rules = 0, pairs = 0

  for (const sheet of document.styleSheets) {
    let cssRules
    try { cssRules = sheet.cssRules } catch { continue }  // cross-origin sheet
    for (const rule of cssRules) {
      if (!rule.selectorText || !/:(hover|focus-visible)\b/.test(rule.selectorText)) continue

      const decls = ruleColours(rule.style)
      if (!decls.length) continue
      rules++
      // An `outline` with an offset and a `box-shadow` are painted OUTSIDE the
      // box: they are seen against the parent's background, not the element's
      // own. Comparing them against the element gave 1.00:1 on the selected tab
      // —amber ring over amber button— and there is no defect there at all: the
      // ring falls on the sidebar, which is dark.


      for (const sel of rule.selectorText.split(',')) {
        const base = sel.replace(/:(hover|focus-visible)\b/g, '').trim()
        if (!base) continue
        let elements
        try { elements = root.querySelectorAll(base) } catch { continue }
        for (const el of elements) {
          const r = el.getBoundingClientRect()
          if (!r.width || !r.height) continue
          /* A hover rule usually changes SEVERAL things at once: the checked
             checkbox tints a `border-color` that was already worth the same and
             at the same time adds a `box-shadow` ring that is visible. Keeping
             the first property gave 1.00:1 and a defect that does not exist. Each
             channel is measured and the one that changes MOST wins: if a single
             one is perceived, the state is perceived. */
          let best = null
          for (const decl of decls) {
            const declared = resolveColour(decl.color, el)
            const ld = lum(declared)
            if (ld == null) continue
            const outside = decl.prop.startsWith('outline') || decl.prop === 'box-shadow'
            const resting = realBackground(outside ? (el.parentElement ?? el) : el)
            const cr = +ratio(ld, lum(resting)).toFixed(3)
            if (best == null || cr > best.cr) best = { cr, decl, declared, resting }
          }
          if (best == null) continue
          pairs++
          const { cr, decl, declared, resting } = best
          if (cr >= minimum) continue
          const k = `${sel}|${cr}`
          if (seen.has(k)) continue
          seen.add(k)
          weak.push({
            cr,
            estado: /focus-visible/.test(sel) ? 'focus' : 'hover',
            selector: sel.trim().slice(0, 60),
            declarado: `${decl.prop}: ${decl.color} = ${declared}`,
            reposo: resting,
            ejemplo: (el.textContent || el.tagName).trim().slice(0, 30),
          })
        }
      }
    }
  }
  // The counts are in the response on purpose: a sweep that measures no pairs
  // also returns [], and that is not a pass, it is a dead tool.
  return { reglas: rules, pares: pairs, flojos: weak.sort((a, b) => a.cr - b.cr) }
}
