/*
Does the same thing look the same on every screen?

The other tools in `dev/` look at one screen and answer whether it is right. This
one looks at ALL of them and answers something different: whether the same object
—a panel, a table header, a count— is painted the same everywhere.

It was needed because the console was written screen by screen, and each one
solved on its own what had already been solved next door. Measured before fixing
it: the bordered container was defined SEVEN times with four different looks, the
small-caps label FOURTEEN times with three sizes and four letter-spacings, and
the count footer EIGHT times with four treatments. None of that is visible to a
screen-by-screen review, because on each screen, taken alone, everything looks
right.

    await firmas()        groups each family by look and says how many there are

The CONTROL families —text field, textarea, dropdown, checkbox, radio, alert—
were added later, and they are the ones that caught the last batch: the textarea
was painted by hand on four screens, with radius 6 instead of 8 and without the
inset shadow every other field carries. None of the earlier families saw it,
because a textarea, alone on its screen, looks right.

What it returns are GROUPS, not a verdict: two signatures can both be right —the
data table and the editable one are two objects on purpose— and a single one can
be wrong if it is ugly. What must not happen is that there are five without
anyone having decided so.

And you have to know how to read it. A signature ending in "td —" is not a
different density: it is a table no cell sample could be taken from, so the same
table appears twice. With today's data, `tabla: 4` is really two —the data one
and the editable one— each with and without a sample.

Paste it into the browser console or pass it to `browser_evaluate`, screen by
screen, accumulating the result.
*/

const css = (e) => getComputedStyle(e)

/** The visual signature of every family present on the current screen. */
function screenSignatures() {
  const root = document.querySelector('main') ?? document.body
  const out = {}
  const note = (family, signature) => {
    out[family] = out[family] ?? new Set()
    out[family].add(signature)
  }

  /* The bordered container: panel, block or form fieldset. */
  for (const c of root.querySelectorAll('[class*="_panel_"], [class*="_block_"]')) {
    const s = css(c)
    const head = c.querySelector('[class*="_ph_"], [class*="_blockTitle_"], [class*="_cabecera_"]')
    /* The title is not always an `h2`: in Permissions it is a `span` inside an
       `h4`, and in a `fieldset` it is the `legend` itself. */
    const t =
      head?.tagName === 'LEGEND' ? head : (head?.querySelector('h2, h3') ?? head?.firstElementChild)
    note(
      'panel',
      [
        s.boxShadow === 'none' ? 'no-shadow' : 'shadow',
        s.borderRadius,
        head ? css(head).backgroundColor : 'no-header',
        t ? `${css(t).fontSize}/${css(t).fontWeight}/${css(t).textTransform}/${css(t).letterSpacing}` : '-',
      ].join(' | '),
    )
  }

  /* The table: header and cell density. */
  for (const t of root.querySelectorAll('table')) {
    const th = t.querySelector('thead th')
    /* The sample cell, skipping the "there is nothing" row: its padding is its
       own, taller on purpose, and it came out as one more density. */
    const td = [...t.querySelectorAll('tbody td')].find((c) => !/_sinFilas_/.test(c.className))
    if (!th) continue
    note(
      'tabla',
      `th ${css(th).fontSize}/${css(th).fontWeight}/${css(th).letterSpacing}/${css(th).backgroundColor}` +
        ` · td ${td ? css(td).padding : '—'}`,
    )
  }

  /* The actions column: what is left over between the last control and the edge. */
  for (const t of root.querySelectorAll('table')) {
    const row = t.querySelector('tbody tr')
    const last = row ? [...row.querySelectorAll('td')].pop() : null
    const group = last?.querySelector('[class*="_acciones_"]')
    if (!group) continue
    note('acciones', `${Math.round(t.getBoundingClientRect().right - group.getBoundingClientRect().right)}px from the edge`)
  }

  /* The count that goes with a table. Its TEXT changes on purpose —the three
     vocabularies are upstream literals—; its look does not. */
  for (const n of root.querySelectorAll('div, span, b')) {
    if (n.children.length > 0) continue
    /* With the colon and the number: without them, "Total Queries" —the label of
       a Dashboard tile— passed for a count and showed up as a separate signature
       that did not exist. */
    if (!/^(Total [A-Za-z ]+: ?\d|\d+ zones|\d+-\d+ \()/.test((n.textContent || '').trim())) continue
    note('recuento', `${css(n).fontSize}/${css(n).fontWeight}/${css(n).color}`)
  }

  /*
  The form controls. This family was not here, and it was the one that was
  missing: the textarea was painted by hand in Settings, DHCP, Administration and
  the lists screens —radius 6 instead of 8, one step less in size, without the
  inset shadow every other field carries— and neither the screenshots nor the
  other families said so, because on each screen, alone, the textarea looked
  right.

  The signature does not include WIDTH: that one really is per-field (upstream
  pins numeric fields at 80-100 px and leaves text fields wide). It includes the
  box.
  */
  const box = (e) => {
    const s = css(e)
    return [
      s.borderRadius,
      s.padding,
      s.fontSize,
      s.borderWidth,
      s.boxShadow === 'none' ? 'no-inset' : 'inset',
    ].join(' | ')
  }
  for (const e of root.querySelectorAll('input[type=text], input[type=number], input[type=password], input:not([type])')) {
    note('campo-text', box(e))
  }
  for (const e of root.querySelectorAll('textarea')) note('campo-area', box(e))
  for (const e of root.querySelectorAll('[class*="_disparador_"], select')) note('campo-lista', box(e))

  /*
  The checkbox or radio row.

  A setting and a row selection are NOT the same family, even though both are an
  `input[type=checkbox]` inside a `label`: the setting changes how the server
  behaves and stays put, the selection lasts one click. They are measured apart
  because otherwise the two legitimate exceptions of the table checkbox —40 px in
  the data cell, 0 in the header one, both deliberate and documented in
  `ui/Table.module.css`— come out as two more signatures and bury any real drift
  in the setting checkboxes under the noise.
  */
  for (const e of root.querySelectorAll('input[type=checkbox], input[type=radio]')) {
    const row = e.closest('label')
    if (!row) continue
    const s = css(row)
    const inTable = row.closest('td, th') != null
    note(
      inTable ? 'row-checkbox' : e.type === 'radio' ? 'radio' : 'settings-checkbox',
      `${s.minHeight} | ${s.gap} | ${s.fontSize} | ${s.color}`,
    )
  }

  /*
  The "Note!"/"Warning!" alert: same block and same inset inside its panel.

  What is measured is the RESULT —how many pixels from the panel its edge sits—
  and not the parent's `margin-left`, which was the first attempt and gave a
  false difference: in Settings the gap comes from a margin on the alerts
  wrapper, and in About from padding on the panel body, i.e. the same place by
  two mechanisms.
  */
  for (const e of root.querySelectorAll('[class*="_alerta_"], [role=note], [class*="_alert"]')) {
    const panel = e.closest('[class*="_panel_"], [class*="_block_"]')
    const inset = panel
      ? `${Math.round(e.getBoundingClientRect().left - panel.getBoundingClientRect().left)}px from the panel`
      : 'loose on the page'
    note('aviso', `${css(e).borderRadius} | ${inset}`)
  }

  /* The screen title. */
  const h1 = root.querySelector('h1')
  if (h1) note('titulo', `${css(h1).fontSize}/${css(h1).fontWeight}/${css(h1).letterSpacing}`)

  /*
  And the gap under that title, which had also drifted apart: six screens had it
  at 38 px and twelve at 24, because those six put the header inside a `flex`
  container with `gap`, and in flex the gap ADDS to the child's margin. It is
  measured against the next sibling and not against "the first bordered box",
  which was the first attempt: that `find()` picked different elements on
  different screens and gave two false measurements in a row.
  */
  const header = h1?.closest('[class*="_hrow_"]')
  const next = header?.nextElementSibling
  if (header && next) {
    note(
      'gap-under-the-title',
      `${Math.round(next.getBoundingClientRect().top - header.getBoundingClientRect().bottom)}px`,
    )
  }

  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v]]))
}

/** Accumulates the signatures of several screens into a single report. */
function merge(reports) {
  const total = {}
  for (const { ruta, firmas } of reports) {
    for (const [family, list] of Object.entries(firmas)) {
      total[family] = total[family] ?? {}
      for (const f of list) {
        total[family][f] = total[family][f] ?? []
        total[family][f].push(ruta)
      }
    }
  }
  return Object.entries(total).map(([family, signatures]) => ({
    familia: family,
    cuantas: Object.keys(signatures).length,
    firmas: Object.entries(signatures).map(([f, routes]) => `${f}  →  ${routes.join(', ')}`),
  }))
}
