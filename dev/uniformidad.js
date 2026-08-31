/*
¿Se ve igual lo mismo en todas las pantallas?

Las otras herramientas de `dev/` miran una pantalla y contestan si está bien.
Ésta mira TODAS y contesta algo distinto: si el mismo objeto —un panel, una
cabecera de tabla, un recuento— se pinta igual en todas partes.

Hacía falta porque la consola se escribió pantalla a pantalla, y cada una
resolvió por su cuenta lo que ya estaba resuelto al lado. Medido antes de
arreglarlo: el contenedor con borde estaba definido SIETE veces con cuatro
aspectos distintos, el rótulo en versalitas CATORCE con tres tamaños y cuatro
interletrados, y el pie de recuento OCHO con cuatro tratamientos. Nada de eso lo
ve una revisión pantalla a pantalla, porque en cada pantalla, por separado, todo
parece correcto.

    await firmas()        agrupa cada familia por aspecto y dice cuántas hay

Lo que devuelve son GRUPOS, no un veredicto: dos firmas pueden estar bien
—la tabla de datos y la editable son dos objetos a propósito— y una sola puede
estar mal si es fea. Lo que no puede pasar es que haya cinco sin que nadie lo
haya decidido.

Y hay que saber leerlo. Una firma que acaba en «td —» no es una densidad
distinta: es una tabla de la que no se pudo tomar muestra de celda, así que la
misma tabla aparece dos veces. Con los datos de hoy, `tabla: 4` son en realidad
dos —la de datos y la editable—, cada una con y sin muestra.

Se pega en la consola del navegador o se pasa a `browser_evaluate`, pantalla por
pantalla, acumulando el resultado.
*/

const css = (e) => getComputedStyle(e)

/** La firma visual de cada familia presente en la pantalla actual. */
function firmasDeLaPantalla() {
  const raiz = document.querySelector('main') ?? document.body
  const out = {}
  const anota = (familia, firma) => {
    out[familia] = out[familia] ?? new Set()
    out[familia].add(firma)
  }

  /* El contenedor con borde: panel, bloque o fieldset de formulario. */
  for (const c of raiz.querySelectorAll('[class*="_panel_"], [class*="_block_"]')) {
    const s = css(c)
    const cab = c.querySelector('[class*="_ph_"], [class*="_blockTitle_"], [class*="_cabecera_"]')
    /* El título no siempre es un `h2`: en Permissions es un `span` dentro de un
       `h4`, y en un `fieldset` es el propio `legend`. */
    const t =
      cab?.tagName === 'LEGEND' ? cab : (cab?.querySelector('h2, h3') ?? cab?.firstElementChild)
    anota(
      'panel',
      [
        s.boxShadow === 'none' ? 'sin-sombra' : 'sombra',
        s.borderRadius,
        cab ? css(cab).backgroundColor : 'sin-cabecera',
        t ? `${css(t).fontSize}/${css(t).fontWeight}/${css(t).textTransform}/${css(t).letterSpacing}` : '-',
      ].join(' | '),
    )
  }

  /* La tabla: cabecera y densidad de celda. */
  for (const t of raiz.querySelectorAll('table')) {
    const th = t.querySelector('thead th')
    /* La celda de muestra, saltándose la fila de «no hay nada»: su relleno es
       el suyo, más alto a propósito, y salía como una densidad más. */
    const td = [...t.querySelectorAll('tbody td')].find((c) => !/_sinFilas_/.test(c.className))
    if (!th) continue
    anota(
      'tabla',
      `th ${css(th).fontSize}/${css(th).fontWeight}/${css(th).letterSpacing}/${css(th).backgroundColor}` +
        ` · td ${td ? css(td).padding : '—'}`,
    )
  }

  /* La columna de acciones: lo que sobra entre el último control y el borde. */
  for (const t of raiz.querySelectorAll('table')) {
    const fila = t.querySelector('tbody tr')
    const ultima = fila ? [...fila.querySelectorAll('td')].pop() : null
    const grupo = ultima?.querySelector('[class*="_acciones_"]')
    if (!grupo) continue
    anota('acciones', `${Math.round(t.getBoundingClientRect().right - grupo.getBoundingClientRect().right)}px del borde`)
  }

  /* El recuento que acompaña a una tabla. Su TEXTO cambia a propósito —los tres
     vocabularios son literales de upstream—; su aspecto, no. */
  for (const n of raiz.querySelectorAll('div, span, b')) {
    if (n.children.length > 0) continue
    /* Con los dos puntos y el número: sin ellos, «Total Queries» —el rótulo de
       una baldosa del Dashboard— pasaba por recuento y aparecía como una firma
       distinta que no existía. */
    if (!/^(Total [A-Za-z ]+: ?\d|\d+ zones|\d+-\d+ \()/.test((n.textContent || '').trim())) continue
    anota('recuento', `${css(n).fontSize}/${css(n).fontWeight}/${css(n).color}`)
  }

  /* El título de la pantalla. */
  const h1 = raiz.querySelector('h1')
  if (h1) anota('titulo', `${css(h1).fontSize}/${css(h1).fontWeight}/${css(h1).letterSpacing}`)

  /*
  Y el hueco bajo ese título, que también se había separado: seis pantallas lo
  tenían a 38 px y doce a 24, porque las seis meten la cabecera en un contenedor
  `flex` con `gap` y en flex el hueco SE SUMA al margen del hijo. Se mide contra
  el hermano siguiente y no contra «la primera caja con borde», que es lo que se
  intentó primero: ese `find()` cogía elementos distintos en cada pantalla y dio
  dos medidas falsas seguidas.
  */
  const cabecera = h1?.closest('[class*="_hrow_"]')
  const siguiente = cabecera?.nextElementSibling
  if (cabecera && siguiente) {
    anota(
      'hueco-bajo-el-titulo',
      `${Math.round(siguiente.getBoundingClientRect().top - cabecera.getBoundingClientRect().bottom)}px`,
    )
  }

  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v]]))
}

/** Acumula las firmas de varias pantallas en un solo informe. */
function juntar(informes) {
  const total = {}
  for (const { ruta, firmas } of informes) {
    for (const [familia, lista] of Object.entries(firmas)) {
      total[familia] = total[familia] ?? {}
      for (const f of lista) {
        total[familia][f] = total[familia][f] ?? []
        total[familia][f].push(ruta)
      }
    }
  }
  return Object.entries(total).map(([familia, firmas]) => ({
    familia,
    cuantas: Object.keys(firmas).length,
    firmas: Object.entries(firmas).map(([f, rutas]) => `${f}  →  ${rutas.join(', ')}`),
  }))
}
