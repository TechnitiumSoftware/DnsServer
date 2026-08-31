/*
What each screen shows when the server fails.

This is point 12 of the review plan, the only one that said "this has to be
written" and still had not been. The other tools look at a console that works;
this one looks at the one that does not.

What it looks for is NOT that an alert appears. It is the opposite: **that a
failed request does not end up painted as an empty state.** "No data for this
period" and "there is nothing to show because the call fell over" are the same
picture and mean opposite things, and of the two, the first is the one that makes
someone close the tab convinced their DNS has received no queries. It is the same
underlying failure as the squashed "User Details" table: the screen lies without
saying so.

It deliberately does not use Playwright, like the rest of `dev/`: paste it into
the browser console or pass it to `browser_evaluate`. Putting a driver in
`package.json` would show up in the pull request diff.

    romper('api/', 'error')      the server answers 200 with status=error
    romper('api/', '500')        answers 500 with HTML, which is not even JSON
    romper('api/', 'red')        does not answer: fetch rejects
    romper('dashboard', 'error') only what matches that piece of the URL
    arreglar()                   gives back the real fetch

    await queDice()              what is on screen now: alerts, empties and loads

Normal use: `romper(...)`, reload the screen —or navigate back into it— and
`await queDice()`.
*/

const realFetch = window.fetch

/** Replaces `fetch` with one that fails as instructed. */
function romper(pattern = 'api/', mode = 'error') {
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url
    if (!url.includes(pattern)) return realFetch(input, init)

    if (mode === 'red') throw new TypeError('Failed to fetch')

    if (mode === '500') {
      // 500 with an HTML body: the case where not even the JSON can be read.
      return new Response('<html><body>500</body></html>', {
        status: 500,
        headers: { 'Content-Type': 'text/html' },
      })
    }

    // The real case for this API: 200 with the status inside the envelope.
    const body =
      mode === 'invalid-token'
        ? { status: 'invalid-token' }
        : { status: 'error', errorMessage: 'Simulated server failure.' }

    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }
  return `broken: ${pattern} → ${mode}`
}

function arreglar() {
  window.fetch = realFetch
  return 'fixed'
}

const visible = (e) => {
  const r = e.getBoundingClientRect()
  return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'
}

const text = (e) => (e.innerText || '').replace(/\s+/g, ' ').trim()

/**
 * What is on screen. Returns the alerts, the empty states and whether anything
 * is loading, plus the verdict: an empty state with no alert is the finding.
 */
async function queDice(ms = 1500) {
  await new Promise((r) => setTimeout(r, ms))
  const root = document.querySelector('main') ?? document.body

  const alerts = [...document.querySelectorAll('[role="alert"]')]
    .filter(visible)
    .map((e) => text(e).slice(0, 120))

  /*
  And the failure stated WITHOUT a `role="alert"`, which also counts. Settings,
  for example, replaces the whole form with "Unable to load the DNS Server
  settings.", which is a perfectly good way of saying it; looking only for alerts
  called it mute and that was a false positive.
  */
  const stated = /Unable to (load|check|reach)|Failed to|Error!/i.test(text(root))

  /* The console's empty states: `ui/Empty` and the phrases upstream uses for
     "there is nothing here". Searched by class and by phrase, because not all of
     them go through the component. */
  const empties = [...root.querySelectorAll('[class*="_empty_"], [class*="_vacio_"]')]
    .filter(visible)
    .map((e) => text(e).slice(0, 90))

  const byPhrase = /No data for this period|No queries for this period|No .{0,24} found|Nothing to show/i
  const phrases = [...root.querySelectorAll('div, p, td')]
    .filter((e) => e.children.length === 0 && visible(e) && byPhrase.test(text(e)))
    .map((e) => text(e).slice(0, 90))

  const loading = [...root.querySelectorAll('[class*="_loading_"], [aria-busy="true"]')].filter(visible).length

  const allEmpties = [...new Set([...empties, ...phrases])]

  return {
    ruta: location.pathname,
    avisos: alerts,
    vacios: allEmpties,
    cargando: loading,
    /*
    The verdict. An empty state with no alert beside it is the screen saying
    "there is nothing" when what happened is that the call fell over.
    */
    dicho: stated,
    veredicto:
      alerts.length > 0 || stated
        ? 'REPORTS IT'
        : allEmpties.length > 0
          ? 'LIES: shows empty and does not say it failed'
          : loading > 0
            ? 'STUCK LOADING'
            : 'NO ALERT AND NOTHING ELSE',
  }
}
