/*
El censo de diálogos: abre uno por uno TODOS los de la consola y les pasa la
misma batería.

Nació de un fallo propio. Se revisaban «a ojo» los que uno se acordaba de abrir,
y así se coló que la tabla de sesiones de «User Details» no se veía: su
envoltorio medía 831×2 —aplastado a cero— mientras la tabla que contenía medía
814×298. Se veía el rótulo, una línea y «Total Sessions: 3», y ni una fila.

Por eso la comprobación de `aplastados` es la primera de la lista: un elemento
con contenido y sin altura no lo detecta ninguna medida de contraste ni de
espaciado, y es de lo peor que puede pasar —la pantalla miente sin avisar—.

    await censarTodos()          los abre todos y devuelve sólo los problemas
    await censarTodos(true)      además, la ficha de cada uno

Se pega en la consola del navegador o se pasa a `browser_evaluate`.
*/

const espera = (t) => new Promise((r) => setTimeout(r, t))
const hasta = async (fn, ms = 9000) => {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) { const v = fn(); if (v) return v; await espera(120) }
  return null
}

const dialogo = () => document.querySelector('[role="dialog"]')

async function cerrar() {
  const c = document.querySelector('[role="dialog"] [class*="_close_"]')
  if (c) { c.click(); await hasta(() => !dialogo()) }
  document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  await espera(220)
}

async function irSeccion(n) {
  await cerrar()
  for (const t of document.querySelectorAll('[role="tab"]')) {
    if (t.textContent.trim() === n) { t.click(); await espera(1200) }
  }
}

async function irSub(n) {
  await cerrar()
  const b = [...document.querySelectorAll('nav [class*="_sub_"] button')].find((x) => x.textContent.trim() === n)
  if (!b) return false
  b.click(); await espera(1100); return true
}

/** La batería. Devuelve los problemas encontrados, no una nota. */
function revisar() {
  const d = dialogo()
  if (!d) return { problemas: ['no abrió'] }
  const cuerpo = [...d.children].find((c) => /_body_/.test(c.className))
  const pie = [...d.children].find((c) => /_foot_/.test(c.className))
  const r = d.getBoundingClientRect()
  const problemas = []

  /* 1. Aplastados: contenido dentro de una caja sin altura. Es el que se coló. */
  for (const e of d.querySelectorAll('*')) {
    const b = e.getBoundingClientRect()
    if (b.height < 8 && e.scrollHeight > 24 && b.width > 40) {
      problemas.push(`APLASTADO ${e.tagName}.${(typeof e.className === 'string' ? e.className : '').split(' ')[0]} ` +
        `${Math.round(b.width)}×${Math.round(b.height)} con ${e.scrollHeight}px dentro`)
    }
  }

  /* 2. Filas que existen en el DOM y no se ven. */
  for (const t of d.querySelectorAll('table')) {
    const filas = [...t.querySelectorAll('tbody tr')]
    const visibles = filas.filter((f) => f.getBoundingClientRect().height > 4).length
    if (filas.length && visibles < filas.length) {
      problemas.push(`FILAS INVISIBLES ${visibles}/${filas.length}`)
    }
  }

  /* 3. Lo que ya medía `medir()`, si está inyectado. */
  if (typeof medir === 'function') {
    const m = medir(d)
    for (const c of m.contraste) problemas.push(`CONTRASTE ${c.cr} «${c.texto}»`)
    for (const t of m.tactil) problemas.push(`OBJETIVO ${t}`)
    for (const n of m.sinNombre) problemas.push(`SIN NOMBRE ${n.slice(0, 50)}`)
  }

  /* 4. El diálogo no debe rodar: rueda su cuerpo. */
  if (d.scrollHeight > d.clientHeight + 1) problemas.push('RUEDA EL DIÁLOGO ENTERO')
  if (d.scrollWidth > d.clientWidth + 1) problemas.push('DESBORDA EN HORIZONTAL')
  if (r.height > innerHeight) problemas.push(`NO CABE ${Math.round(r.height)} > ${innerHeight}`)

  /* 5. El pie: la acción primero, el descarte después. */
  const botones = pie ? [...pie.querySelectorAll('button')].map((b) => b.textContent.trim()) : []
  if (botones.length > 1 && /^(close|cancel)$/i.test(botones[0])) {
    problemas.push(`PIE AL REVÉS ${botones.join(' · ')}`)
  }

  return {
    titulo: d.querySelector('[class*="_title_"]')?.textContent.trim().slice(0, 34),
    talla: d.getAttribute('data-tamano'),
    caja: `${Math.round(r.width)}×${Math.round(r.height)}`,
    pie: botones.join(' · '),
    ruedaCuerpo: cuerpo ? cuerpo.scrollHeight > cuerpo.clientHeight : false,
    problemas,
  }
}

/** Las recetas para abrir cada diálogo. */
async function abrir(receta) {
  await cerrar()
  if (receta.seccion) await irSeccion(receta.seccion)
  if (receta.sub) await irSub(receta.sub)
  if (receta.antes) { await receta.antes(); await espera(900) }

  const pulsa = (sel, texto) => {
    const b = [...document.querySelectorAll(sel)].find(
      (x) => (x.getAttribute('aria-label') || x.textContent).trim() === texto,
    )
    if (b) b.click()
    return !!b
  }

  if (receta.boton && !pulsa('main button', receta.boton)) return { problemas: [`sin botón «${receta.boton}»`] }

  if (receta.celda) {
    if (!pulsa('main tbody button', receta.celda)) return { problemas: [`sin celda «${receta.celda}»`] }
  }

  if (receta.menu) {
    const [disparador, item] = receta.menu
    if (receta.fila) {
      const f = [...document.querySelectorAll('main tbody tr')].find((x) => x.innerText.includes(receta.fila))
      if (!f) return { problemas: [`sin fila «${receta.fila}»`] }
      const b = [...f.querySelectorAll('button')].find((x) => /Actions/.test(x.getAttribute('aria-label') || ''))
      if (!b) return { problemas: ['sin menú de fila'] }
      b.click()
    } else if (!pulsa('main button', disparador)) {
      return { problemas: [`sin menú «${disparador}»`] }
    }
    const m = await hasta(() => { const l = document.querySelectorAll('[role="menu"]'); return l.length ? l[l.length - 1] : null })
    if (!m) return { problemas: ['el menú no abre'] }
    const it = [...m.querySelectorAll('button')].find((x) => x.textContent.trim() === item)
    if (!it) return { problemas: [`sin «${item}» en el menú`] }
    it.click()
  }

  if (receta.usuario) {
    const b = [...document.querySelectorAll('header button')].find((x) => /Administrator/.test(x.textContent))
    b.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })); b.click()
    const lista = await hasta(() => document.querySelector('[class*="_menuList_"]'))
    if (!lista) return { problemas: ['el menú de usuario no abre'] }
    const it = [...lista.querySelectorAll('button')].find((x) => x.textContent.trim() === receta.usuario)
    if (!it) return { problemas: [`sin «${receta.usuario}»`] }
    it.click()
  }

  if (!await hasta(() => dialogo())) return { problemas: ['no abrió'] }
  await espera(receta.espera ?? 700)
  return revisar()
}

async function censarTodos(recetas, todo = false) {
  const out = []
  for (const receta of recetas) {
    const r = await abrir(receta)
    r.nombre = receta.nombre
    if (todo || r.problemas.length) out.push(r)
  }
  await cerrar()
  return out
}
