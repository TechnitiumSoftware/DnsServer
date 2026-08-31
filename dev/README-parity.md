# Parity checks

## `check-parity-actions.sh` — the one that actually counts

Runs **the same action on both instances** and compares the state the server is
left in, not the bytes of the page. This is the check that makes the project's
governing constraint enforceable: since behaviour does not change, if the body
the new console sends differs by one parameter, the record left behind differs
and it shows up here.

```bash
docker compose up -d
./check-parity-actions.sh
```

It covers fourteen actions: seven creates (including the awkward ones —split TXT,
SVCB with flattened `svcParams`, CAA with its default values—), three edits
(among them disabling a record, which upstream does as a `records/update`
resending the whole record), three deletes (including CNAME, which falls to the
`default` branch and sends no identity parameter at all) and the `options/set`
with all six empty lists travelling as the string `"false"`.

It normalises three things before comparing, and all three because they are not
parity: `lastModified`, the SOA serial and **the server's own name**, which is
embedded in the NS and SOA of every zone and is deliberately different in each
container.

## `check-parity.sh` — only for the preserved files

Compares the content of a path between the two instances. Since phase 0 the
console is ours, so **for `/` it reports `DIFFERENT` and that is the point of the
project**. It still serves for what the build preserves untouched:

```bash
./check-parity.sh /robots.txt   # IDENTICAL
./check-parity.sh /favicon.ico  # IDENTICAL
```

## `parity-login.mjs`

Compares the alerts on the login screen between the new console (5380) and
upstream's (5381). Needs Playwright:

```bash
npm i -D playwright && npx playwright install chromium
node parity-login.mjs
```

It found two real divergences the first time it ran: the "×" button to dismiss
the alert was missing —upstream has it, so its absence was a behavioural
difference— and so was the space between the title and the text.
