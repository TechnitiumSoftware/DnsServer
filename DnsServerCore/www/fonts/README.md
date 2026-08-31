# The console's fonts

- **Archivo** (Omnibus-Type) for the text, variable 300-700 — `OFL-Archivo.txt`
- **IBM Plex Mono** for the data, weights 400 and 600 — `OFL-IBMPlex.txt`

Both under the SIL Open Font License 1.1, which allows packaging and
redistributing them with the software. **65 KB in total.**

## Why they live here and not on a CDN

The server's CSP is `default-src 'self'` with no `font-src`
(`DnsServerCore/DnsWebService.cs:1969-1974`): any font that does not come from
the origin itself is blocked. They have to travel inside `www/`.

## Why these two

The console used the operating system's font, and that is the underlying reason
it read as correct but anonymous: the same letterform as everything else, and a
different one on every machine.

Inter and Geist were ruled out on purpose. Both are excellent and both are
everywhere —Inter is NetBird's, Geist is Vercel's— so using them would have been
swapping one borrowed font for another.

**Archivo** is a slightly narrowed grotesque with marked verticals: it has
presence at small sizes, which is where a zone table is read, and a technical
product character that belongs to nobody else.

**Plex Mono** is half of what this console shows —domains, addresses, serials,
TTLs— and there what matters is that the figures cannot be confused: slashed
zero, one with a base, unmistakable l and 1. On a DNS that is not a typographic
detail, it is reading an address correctly.

Downloaded from the `latin` subset Google Fonts publishes.
