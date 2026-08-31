/*
Have we dropped any of upstream's destinations?

The review plan said "open the same screen in `technitium-ui-ref` and compare by
eye". Things slip past the eye — and they did, big ones: the About panel had lost
eight of its nine links, and the whole `body` footer, with the author's support
and donation addresses inside it.

This does it by list, and without a browser: upstream's console is a single
`index.html` with ALL its panels in the markup, so its destinations are read from
the HTML; ours are read from the application code. No new dependencies —putting
Playwright in `package.json` would show up in the pull request diff— and
therefore runnable anywhere with the reference console up.

    node dev/check-parity-controls.mjs
    REF=http://other:5381 node dev/check-parity-controls.mjs

What it does NOT answer, worth having in front of you before believing a green:

- **It searches ALL the code, not the screen in question.** If an explanation
  appears in two dialogs and falls out of one, this stays green. Verified: the
  DNSKEY TTL text was deliberately removed from "Sign Zone" and it said nothing,
  because the same text lives in "DNSSEC Properties". It bites on what exists in
  only one place, which is how things actually get lost —the About panel lost
  eight links and none of them was anywhere else—.
- Whether a destination present in both points to the same thing from the
  equivalent screen.
- Whether a button that exists in both does the same thing. For behaviour there
  is `check-parity-actions.sh`, which compares server state.
*/
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const REF = process.env.REF ?? 'http://127.0.0.1:5381'
const SOURCE = new URL('../DnsServerCore/webapp/src/', import.meta.url).pathname

/* Destinations upstream has and that must NOT be here, with their reason. Every
   line is a decision, not an oversight: if it is not justified, it is a finding. */
const EXCUSED = new Map([
  // The themes modal goes away with the "a single theme, the dark one" decision.
  // It carries no links of its own, so today this list is deliberately empty:
  // it is left written so that whoever adds an excuse has to reason it out here.
])

function files(dir) {
  const out = []
  for (const n of readdirSync(dir)) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) out.push(...files(p))
    else if (/\.(tsx?|css)$/.test(n)) out.push(p)
  }
  return out
}

const normalise = (u) => u.replace(/\/$/, '').replace(/^http:/, 'https:')

/** The four entities that appear in upstream's texts. */
const decode = (t) =>
  t
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')

/*
The source WITHOUT comments.

A comment is not interface: nobody reads it on screen. While they were in Spanish
it made no difference, because they could not match an English sentence from
upstream; once translated to English it stopped making no difference — a comment
quoting the help text it explains would make a REALLY missing help text match,
and this check would go green for the opposite reason to the one it exists for.

They are stripped before comparing. String literals in the code stay, since that
is exactly where the text being searched for lives.
*/
const withoutComments = (t) =>
  t.replaceAll(/\/\*[\s\S]*?\*\//g, ' ').replaceAll(/^\s*\/\/[^\n]*/gm, ' ')

const ours = files(SOURCE)
  .filter((f) => !/\.test\./.test(f))
  .map((f) => withoutComments(readFileSync(f, 'utf8')))
  .join('\n')

const html = await fetch(`${REF}/`).then((r) => {
  if (!r.ok) throw new Error(`the reference console answers ${r.status} at ${REF}`)
  return r.text()
})

/* Upstream's destinations, with the screen they appear on. */
const theirs = new Map()
for (const m of html.matchAll(/href="((?:https?:|mailto:)[^"]+)"/g)) {
  const url = normalise(m[1])
  if (!theirs.has(url)) theirs.set(url, [])
  /* The nearest container with an id, searching backwards. It is a HINT, not a
     truth: upstream's markup does not close a modal before the next one starts,
     so it serves to go and find it, not to cite it. */
  const before = html.slice(0, m.index)
  const near = [...before.matchAll(/id="(modal\w+|\w*TabPane\w+|footer)"/g)].pop()
  theirs.get(url).push(near ? near[1] : '?')
}

/*
The application's text, reduced to words.

Comparing markup does not work here. JSX splits sentences —`Add{' '}<code>!</code>
character`— and many explanations travel as an ATTRIBUTE (`help="The duration for
which…"`), so stripping the tags to clean up takes with it the very text you came
looking for. Both produced false positives: the first accused the ACL text of
being lost, the second three more that had been in place for months.

Reducing both sides to bare words —no punctuation, no case, no symbols— removes
all of that difference. It adds noise (class names, attributes), but noise can
only produce a false NEGATIVE across eight consecutive words, and that does not
happen.
*/
const asWords = (t) =>
  ' ' +
  t
    .toLowerCase()
    .replace(/&quot;|&#39;|&apos;/g, ' ')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim() +
  ' '

const prose = asWords(ours)

const missing = []
for (const [url] of theirs) {
  if (EXCUSED.has(url)) continue
  // the destination is searched for as-is and without the trailing slash: in the
  // code it may be wrapped by the formatter, but a URL is never split.
  const raw = url.replace(/^https:/, 'http:')
  if (ours.includes(url) || ours.includes(raw) || ours.includes(`${url}/`)) continue
  missing.push(url)
}

const total = theirs.size
for (const url of missing) {
  console.log(`  MISSING  ${url}   (upstream, near: ${[...new Set(theirs.get(url))].join(', ')})`)
}

console.log(
  missing.length === 0
    ? `DESTINATION PARITY: all ${total} of upstream's are in the new console.`
    : `DESTINATION PARITY: ${missing.length} of ${total} missing.`,
)

/*
And the help texts. Upstream does not mark them with a class of its own: they are
`div`s carrying the Bootstrap grid offset (`col-sm-offset-N col-sm-M`), which
turns out to be a reliable signature because nothing else goes there.

They are compared by a run of words from the middle, not by the whole sentence:
the beginning and the end are what gets reworded most while laying out, and what
matters is whether the explanation is there or not.
*/
const HELP = [...html.matchAll(/<div class="col-sm-offset-\d+ col-sm-\d+"[^>]*>([\s\S]*?)<\/div>/g)]
  .map((m) => m[1].replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' '))
  .map((t) => decode(t).replace(/\s+/g, ' ').trim())
  .filter((t) => t.length > 40)

const missingHelp = HELP.filter((t) => {
  const words = asWords(t).trim().split(' ')
  if (words.length < 12) return false
  // three runs spread out: if NONE is there, the explanation is not there
  const runs = [words.slice(2, 10), words.slice(6, 14), words.slice(-8)]
  return !runs.some((p) => prose.includes(` ${p.join(' ')} `))
})

console.log('')
for (const t of missingHelp) console.log(`  MISSING  help: ${t.slice(0, 120)}…`)
console.log(
  missingHelp.length === 0
    ? `HELP PARITY: all ${HELP.length} of upstream's texts are present.`
    : `HELP PARITY: ${missingHelp.length} of ${HELP.length} missing.`,
)

/*
And each field's EXAMPLE, which is what upstream puts in `placeholder`.

Added after finding thirty-four of them lost, and some were not decoration: the
one on "Add Zone" read `example.com or 192.168.0.0/24 or 2001:db8::/64`, which is
how you discover that field takes a reverse zone in CIDR form, and the one on
"Certificate Association Data" carried the example hex and the PEM alternative.
Without them the field does not explain what it expects.

It compares by VALUE against the whole source, with the same limitation as the
other two checks and for the same reason: working out which component each field
ends up in would require understanding the JSX. That lets through the case where
the example is present but on another field —it happened with "confirm password",
which existed in "Add User" and was missing from "Change Password"— so a value
repeated across several fields has to be looked at by eye. What it does catch,
and what was needed, is the wholesale loss.
*/
const EXAMPLES = new Map()
for (const m of html.matchAll(/<(?:input|textarea)[^>]*>/g)) {
  const ph = /placeholder="([^"]*)"/.exec(m[0])
  if (!ph) continue
  const id = /id="([^"]*)"/.exec(m[0])
  /* Upstream's image was built on Windows and its multi-line examples carry
     CRLF; our tree is LF. It is the same normalisation `dev/check-parity.sh`
     does, and without it the four multi-line examples came out as lost over a
     carriage return. */
  const value = decode(ph[1]).replace(/\r\n/g, '\n')
  if (value.trim().length < 1) continue
  if (!EXAMPLES.has(value)) EXAMPLES.set(value, id ? id[1] : '?')
}

/* The forwarder example is rewritten by `zone.js:139-152` depending on the
   protocol, and the same is done here in `forwarderExample`: the one in the HTML
   is only the initial value. */
const DYNAMIC = new Set(['8.8.8.8'])

const missingExample = [...EXAMPLES].filter(
  ([value]) => !DYNAMIC.has(value) && !ours.includes(value.split('\n')[0]),
)

console.log('')
for (const [value, id] of missingExample) {
  console.log(`  MISSING  example for ${id}: ${value.split('\n')[0].slice(0, 60)}`)
}
console.log(
  missingExample.length === 0
    ? `EXAMPLE PARITY: all ${EXAMPLES.size} of upstream's are present.`
    : `EXAMPLE PARITY: ${missingExample.length} of ${EXAMPLES.size} missing.`,
)

process.exit(missing.length + missingHelp.length + missingExample.length === 0 ? 0 : 1)
