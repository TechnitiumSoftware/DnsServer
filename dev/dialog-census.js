/*
The dialog census: opens EVERY dialog in the console one by one and runs the same
battery of checks on each.

It was born from a mistake of our own. The ones you happened to remember to open
were reviewed "by eye", and that is how it slipped through that the sessions
table in "User Details" was not visible: its wrapper measured 831×2 —squashed to
zero— while the table inside it measured 814×298. You could see the label, one
line and "Total Sessions: 3", and not a single row.

That is why the `squashed` check is first on the list: an element with content and
no height is not detected by any contrast or spacing measurement, and it is about
the worst thing that can happen —the screen lies without saying so—.

    await censarTodos()          opens them all and returns only the problems
    await censarTodos(true)      plus the record for each one

Paste it into the browser console or pass it to `browser_evaluate`.
*/

const wait = (t) => new Promise((r) => setTimeout(r, t))
const until = async (fn, ms = 9000) => {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) { const v = fn(); if (v) return v; await wait(120) }
  return null
}

const dialog = () => document.querySelector('[role="dialog"]')

async function close() {
  const c = document.querySelector('[role="dialog"] [class*="_close_"]')
  if (c) { c.click(); await until(() => !dialog()) }
  document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  await wait(220)
}

async function goToSection(n) {
  await close()
  for (const t of document.querySelectorAll('nav[aria-label="Sections"] a')) {
    if (t.textContent.trim() === n) { t.click(); await wait(1200) }
  }
}

async function goToSub(n) {
  await close()
  const b = [...document.querySelectorAll('nav [class*="_sub_"] a')].find((x) => x.textContent.trim() === n)
  if (!b) return false
  b.click(); await wait(1100); return true
}

/** The battery. Returns the problems found, not a score. */
function inspect() {
  const d = dialog()
  if (!d) return { problems: ['did not open'] }
  const body = [...d.children].find((c) => /_body_/.test(c.className))
  const foot = [...d.children].find((c) => /_foot_/.test(c.className))
  const r = d.getBoundingClientRect()
  const problems = []

  /* 1. Squashed: content inside a box with no height. This is the one that slipped through. */
  for (const e of d.querySelectorAll('*')) {
    const b = e.getBoundingClientRect()
    if (b.height < 8 && e.scrollHeight > 24 && b.width > 40) {
      problems.push(`SQUASHED ${e.tagName}.${(typeof e.className === 'string' ? e.className : '').split(' ')[0]} ` +
        `${Math.round(b.width)}×${Math.round(b.height)} with ${e.scrollHeight}px inside`)
    }
  }

  /* 2. Rows that exist in the DOM and are not visible. */
  for (const t of d.querySelectorAll('table')) {
    const rows = [...t.querySelectorAll('tbody tr')]
    const visible = rows.filter((f) => f.getBoundingClientRect().height > 4).length
    if (rows.length && visible < rows.length) {
      problems.push(`INVISIBLE ROWS ${visible}/${rows.length}`)
    }
  }

  /* 3. What `measure()` already measured, if it is injected. */
  if (typeof measure === 'function') {
    const m = measure(d)
    for (const c of m.contrast) problems.push(`CONTRAST ${c.cr} «${c.text}»`)
    for (const t of m.target) problems.push(`TARGET ${t}`)
    for (const n of m.unnamed) problems.push(`NO NAME ${n.slice(0, 50)}`)
  }

  /* 4. The dialog must not scroll: its body scrolls. */
  if (d.scrollHeight > d.clientHeight + 1) problems.push('THE WHOLE DIALOG SCROLLS')
  if (d.scrollWidth > d.clientWidth + 1) problems.push('OVERFLOWS HORIZONTALLY')
  if (r.height > innerHeight) problems.push(`DOES NOT FIT ${Math.round(r.height)} > ${innerHeight}`)

  /* 5. The footer: the action first, the dismissal after. */
  const buttons = foot ? [...foot.querySelectorAll('button')].map((b) => b.textContent.trim()) : []
  if (buttons.length > 1 && /^(close|cancel)$/i.test(buttons[0])) {
    problems.push(`FOOTER REVERSED ${buttons.join(' · ')}`)
  }

  return {
    titulo: d.querySelector('[class*="_title_"]')?.textContent.trim().slice(0, 34),
    talla: d.getAttribute('data-size'),
    caja: `${Math.round(r.width)}×${Math.round(r.height)}`,
    pie: buttons.join(' · '),
    ruedaCuerpo: body ? body.scrollHeight > body.clientHeight : false,
    problems: problems,
  }
}

/** The recipes for opening each dialog. */
async function open(recipe) {
  await close()
  if (recipe.seccion) await goToSection(recipe.seccion)
  if (recipe.sub) await goToSub(recipe.sub)
  if (recipe.antes) { await recipe.antes(); await wait(900) }

  const press = (sel, text) => {
    const b = [...document.querySelectorAll(sel)].find(
      (x) => (x.getAttribute('aria-label') || x.textContent).trim() === text,
    )
    if (b) b.click()
    return !!b
  }

  if (recipe.button && !press('main button', recipe.button)) return { problems: [`no button «${recipe.button}»`] }

  if (recipe.cell) {
    if (!press('main tbody button', recipe.cell)) return { problems: [`no cell «${recipe.cell}»`] }
  }

  if (recipe.menu) {
    const [trigger, item] = recipe.menu
    if (recipe.row) {
      const f = [...document.querySelectorAll('main tbody tr')].find((x) => x.innerText.includes(recipe.row))
      if (!f) return { problems: [`no row «${recipe.row}»`] }
      const b = [...f.querySelectorAll('button')].find((x) => /Actions/.test(x.getAttribute('aria-label') || ''))
      if (!b) return { problems: ['no row menu'] }
      b.click()
    } else if (!press('main button', trigger)) {
      return { problems: [`no menu «${trigger}»`] }
    }
    const m = await until(() => { const l = document.querySelectorAll('[role="menu"]'); return l.length ? l[l.length - 1] : null })
    if (!m) return { problems: ['the menu does not open'] }
    const it = [...m.querySelectorAll('button')].find((x) => x.textContent.trim() === item)
    if (!it) return { problems: [`no «${item}» in the menu`] }
    it.click()
  }

  if (recipe.user) {
    const b = [...document.querySelectorAll('header button')].find((x) => /Administrator/.test(x.textContent))
    b.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })); b.click()
    const list = await until(() => document.querySelector('[class*="_menuList_"]'))
    if (!list) return { problems: ['the account menu does not open'] }
    const it = [...list.querySelectorAll('button')].find((x) => x.textContent.trim() === recipe.user)
    if (!it) return { problems: [`no «${recipe.user}»`] }
    it.click()
  }

  if (!await until(() => dialog())) return { problems: ['did not open'] }
  await wait(recipe.espera ?? 700)
  return inspect()
}

async function censarTodos(recipes, all = false) {
  const out = []
  for (const recipe of recipes) {
    const r = await open(recipe)
    r.name = recipe.name
    if (all || r.problems.length) out.push(r)
  }
  await close()
  return out
}
