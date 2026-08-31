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

Las familias de CONTROL —campo de texto, área, lista, casilla, radio, aviso— se
añadieron después, y son las que cazaron la última tanda: el área de texto se
pintaba a mano en cuatro pantallas, con radio 6 en vez de 8 y sin la sombra
interior que llevan todos los demás campos. Ninguna de las familias anteriores
lo veía, porque un área, en su pantalla y sola, parece correcta.

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

  /*
  Los controles de formulario. Esta familia no estaba, y era la que faltaba: el
  área de texto se pintaba a mano en Settings, DHCP, Administration y Listas
  —radio 6 en vez de 8, un punto menos de cuerpo, sin la sombra interior que
  llevan todos los demás campos—, y ni las capturas ni las otras familias lo
  decían, porque en cada pantalla, sola, el área parecía correcta.

  La firma no incluye el ANCHO: eso sí es propio de cada campo (upstream fija
  80-100 px a los numéricos y deja anchos los de texto). Incluye la caja.
  */
  const caja = (e) => {
    const s = css(e)
    return [
      s.borderRadius,
      s.padding,
      s.fontSize,
      s.borderWidth,
      s.boxShadow === 'none' ? 'sin-hundido' : 'hundido',
    ].join(' | ')
  }
  for (const e of raiz.querySelectorAll('input[type=text], input[type=number], input[type=password], input:not([type])')) {
    anota('campo-texto', caja(e))
  }
  for (const e of raiz.querySelectorAll('textarea')) anota('campo-area', caja(e))
  for (const e of raiz.querySelectorAll('[class*="_disparador_"], select')) anota('campo-lista', caja(e))

  /*
  La fila de casilla o de radio.

  Un ajuste y una selección de fila NO son la misma familia, aunque los dos sean
  un `input[type=checkbox]` dentro de un `label`: el ajuste cambia cómo se
  comporta el servidor y se queda puesto, la selección dura un clic. Se miden
  aparte porque si no, las dos excepciones legítimas de la casilla de tabla —40
  px en la celda de datos, 0 en la de cabecera, las dos a propósito y
  documentadas en `ui/Table.module.css`— salen como dos firmas más y entierran
  cualquier deriva real de las casillas de ajuste bajo el ruido.
  */
  for (const e of raiz.querySelectorAll('input[type=checkbox], input[type=radio]')) {
    const fila = e.closest('label')
    if (!fila) continue
    const s = css(fila)
    const enTabla = fila.closest('td, th') != null
    anota(
      enTabla ? 'casilla-de-fila' : e.type === 'radio' ? 'radio' : 'casilla-de-ajuste',
      `${s.minHeight} | ${s.gap} | ${s.fontSize} | ${s.color}`,
    )
  }

  /*
  El aviso «Note!»/«Warning!»: mismo bloque y misma sangría dentro de su panel.

  Se mide el RESULTADO —a cuántos píxeles del panel queda su borde— y no el
  `margin-left` del padre, que fue el primer intento y dio una diferencia falsa:
  en Settings el hueco lo pone un margen del envoltorio de avisos y en About un
  relleno del cuerpo del panel, o sea el mismo sitio por dos mecanismos.
  */
  for (const e of raiz.querySelectorAll('[class*="_alerta_"], [role=note], [class*="_alert"]')) {
    const panel = e.closest('[class*="_panel_"], [class*="_block_"]')
    const sangria = panel
      ? `${Math.round(e.getBoundingClientRect().left - panel.getBoundingClientRect().left)}px del panel`
      : 'suelto en la página'
    anota('aviso', `${css(e).borderRadius} | ${sangria}`)
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
