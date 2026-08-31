# Tools for the screen-by-screen review

The procedure lives in
`docs/superpowers/plans/2026-08-26-technitium-ui-revision-pantalla-a-pantalla.md`
in ORBITLAB. Only what gets executed lives here.

## `medir-pantalla.js`

Everything a number can answer about a screen: real contrast of every piece of
text, spacing outside the token scale, hit-area size of every control, controls
with no accessible name, horizontal overflow and vertical rhythm.

Paste it into the browser console, or pass the whole thing to `browser_evaluate`:

    medir()            // the screen currently open
    await recorrer()   // the twelve sections in a row

For a dialog, tell it which root to use:

    medir(document.querySelector('[role=dialog]'))

And for a state —hover, focus— point at it first and compare against rest:

    medirEstado(document.querySelector('[role=menu] button'), 'rgb(25,28,31)')

**What this does NOT answer**: whether the screen makes sense, whether the data
dominates over the controls, whether the empty state says what to do. That comes
from looking at the screenshot.

## The state you need before starting

Without preparing it, twelve dialogs cannot even be opened. Measured on
2026-08-26 in the `dev` container: zero signed zones, zero DHCP leases, no
cluster. The preparation commands are in the plan, section 1.

**Never against LXC 101.** Only against the disposable instances in
`compose.yaml`.
