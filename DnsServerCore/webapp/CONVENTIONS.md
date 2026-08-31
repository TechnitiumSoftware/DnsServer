# How this console is built

Read this through before touching anything. It is short and it saves you the
mistakes that have already been made.

## The rule that rules them all: design only, zero functionality

This console **replaces the Technitium DNS Server interface without changing what
it does**. Same controls, same steps, **same texts**, same validation order. Any
behavioural difference from the upstream console is a bug, even when it looks
like an improvement.

If you catch yourself thinking "while I am here, this could be better": no. That
is a different job.

## Where the reference is

The old `www/` **is no longer in the tree**. You read it from the history:

```bash
git show upstream/master:DnsServerCore/www/js/zone.js
git show upstream/master:DnsServerCore/www/index.html
```

**The alert texts are contract.** Pull them out of there with
`grep -o 'showAlert("[^"]*", "[^"]*", "[^"]*"'` and copy them literally, without
rewording.

## Do not assume the shape of the responses: check it

There are two disposable instances in `dev/`:

- `dev` at <http://127.0.0.1:5380> — serves our build
- `ref` at <http://127.0.0.1:5381> — the upstream console, untouched

User `admin`, password `technitium-ui-dev`. Bring them up with
`docker compose up -d` from `dev/`.

```bash
T=$(curl -s "http://127.0.0.1:5381/api/user/login?user=admin&pass=technitium-ui-dev&includeInfo=false" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s "http://127.0.0.1:5381/api/zones/list?token=$T" | python3 -m json.tool | head -40
```

Three assumptions that have already turned out false, so you do not repeat them:

1. **Not everything comes wrapped in `response`.** `user/login`,
   `user/session/get` and `status` return the payload **flat**. Everything else
   does wrap it. That is why `apiRequest` **unwraps nothing**: it hands over the
   JSON as it came.
2. The second-factor literal is **`2fa-required`**, not `two-factor-auth-required`.
3. The statistics are flushed **by the minute**. A `dig` you just ran does not
   show on the Dashboard until the next flush; do not conclude something is broken.

## Upstream behaviours discovered along the way

Write down here whatever you find. What is already known:

- **Optional fields that look required.** In `apps/list`, the `updateVersion`,
  `updateUrl` and `updateAvailable` fields **only exist** if the app is in the
  store catalog and there is a compatible version there; an app installed from
  your own zip never brings them, and if the catalog query exhausts its 5 s
  timeout the list arrives whole but without them on any app. Typing them as
  required is a guaranteed bug. Be suspicious of every field you have only seen
  once.
- **A text field can come back as `null`.** `apps/config/get` returns
  `config: null` as soon as someone saves an empty configuration.
- **The upload endpoints are POST-only**: by GET the server answers **404**, not
  a JSON error.
- **On uploads, the file field name does not matter**: the server takes
  `Form.Files[0]`. But **do not set `Content-Type` by hand** or the `boundary`
  is lost and the server says the file is missing.
- **Deleting something that does not exist usually answers `ok`**, not an error.
- **There are two different paginations.** `zones/list` paginates on the server
  (`pageNumber`, `zonesPerPage`) and its paging fields **only appear if you send
  `pageNumber`**. `zones/records/get`, on the other hand, **does not paginate**:
  it is asked for with `listZone=true` and paginated on the client.
- **Where an alert comes out is not cosmetic**: in upstream, a modal's alerts
  come out inside the modal and a screen's come out on the screen. Honour it.
- **The server can return a domain different from the one you asked for.** When
  navigating the cache/allowed/blocked tree, `WebServiceOtherZonesApi.cs`
  **walks down on its own** while the node has no records and has exactly one
  child. Always draw `response.domain`, **never** the domain you asked for, or
  the tree and the table fall out of sync.
- **The same field can have two types depending on the endpoint.** In
  `cache/list` the `ttl` is an already-composed string (`"218 (3m38s)"`); in
  `allowed/list` and `blocked/list` it is a number with `ttlString` apart. Same
  with a SOA's `refresh`, `retry`, `expire` and `minimum`. Typing the records
  with a single shape is a guaranteed bug.
- **`0001-01-01T00:00:00` is .NET's `default(DateTime)`**: it means "never", not
  year 1.
- **Visibility rules that look the same and are not**: deleting a node is
  offered in cache if the node is not the root, and in allowed/blocked if the
  node has records. Do not make them uniform without looking.
- **A count may not be where you draw it.** `blocked/list` only reads the
  manually blocked zones; the downloaded block lists are counted **only** in
  `dashboard/stats/get` (`blockListZones`).
- **Careful with replicating the intent instead of the behaviour.** In
  `other-zones.js` there are three `domain.toLowerCase();` **without assigning
  the result**: they do nothing. What the code does is replicated, not what it
  looks like it wants to do.
- **`settings/get` OMITS the null keys**, it does not send them as `null`:
  fields like `temporaryDisableBlockingTill` or `blockListNextUpdatedOn` simply
  do not appear on a freshly installed server. Others do arrive as an explicit
  `null`. Declaring them required fails against a new install.
- **Careful with `\r\n` when replicating a list textarea.** Upstream builds its
  textareas with `\r\n`, but the browser normalises to `\n` when reading the
  value of a `<textarea>` from the DOM, and its cleanup only substitutes `\n`.
  In React there is no intermediate DOM to normalise: copying the literal
  `\r\n` sends `forwarders=1.1.1.1%0D,8.8.8.8%0D` to the server. **It bites any
  screen with lists in a textarea.**
- **An empty list travels as the string `"false"`**, it is not omitted: it comes
  out of concatenating a boolean into the query. With three exceptions that fall
  to their default value.
- **A screen with sub-tabs can be ONE SINGLE form.** In Settings, "Save" sends
  the fields of all nine sub-tabs wherever you are. Chopping it up per tab would
  change what gets saved.
- **An action bar can mix different permissions**: in Settings, saving requires
  `Settings.canModify`, flushing the cache `Cache.canDelete` and the backup
  `Settings.canDelete`.
- **Asymmetric permissions**: some actions ask for `Delete` where you would
  expect `Modify`, and `apps/list` is allowed with read permission on Apps,
  Zones **or** Logs. Do not deduce the permission: look at it.
- **Not every endpoint returns JSON.** `logs/download` answers `text/plain` with
  the file when it goes well and `application/json` with the usual envelope when
  it fails. It cannot go through `apiRequest`: that would do `res.json()` and
  turn any log into a network failure. Upstream asks for it with
  `isTextResponse` and, if what arrives carries `status`, draws it **formatted
  inside the viewer itself**, as if it were the file's content
  (logs.js:170-172). The error does not come out as an alert.
- **Two endpoints of the same family can call the same datum differently**: the
  log file is asked for with `fileName` in `logs/download` and with `log` in
  `logs/delete`. And `logs/list` returns the name **without extension**, which
  is the one to send in both.
- **Confirming or not confirming is not symmetric.** In DHCP, disabling a scope
  and deleting it both ask; **enabling it asks nothing** (dhcp.js:583 vs 615).
  Only the path that cuts the service asks.
- **`dhcp/scopes/set` is a PARTIAL update**: each field is applied only if it
  comes in the request (`WebServiceDhcpApi.cs:390-650`), so a body with only
  `name` and `newName` renames without touching anything else —checked against a
  v15.4 instance. Upstream always sends all 36. And **a scope created with this
  endpoint is born enabled**, even though nothing says so.
- **`dhcp/scopes/get` OMITS fifteen optional keys** instead of sending them
  `null`: `domainName`, `domainSearchList`, `serverAddress`, `serverHostName`,
  `bootFileName`, `routerAddress`, `dnsServers`, `winsServers`, `ntpServers`,
  `ntpServerDomainNames`, `staticRoutes`, `vendorInfo`, `capwapAcIpAddresses`,
  `tftpServerAddresses`, `genericOptions` and `exclusions`. `reservedLeases` is
  the exception: it is always written, even as `[]`. Same for `interfaceAddress`
  in `scopes/list`.
- **A field can be omitted on purpose when saving**: with "Use This DNS Server"
  checked, upstream **does not send `dnsServers`** (dhcp.js:565). The server
  keeps the stored ones and `scopes/get` still returns them, so the list you see
  on screen is not the one that was just sent.
- **"Deleting something that does not exist answers `ok`" has exceptions.**
  `dhcp/scopes/delete` on a non-existent scope answers `ok`, but
  `dhcp/leases/remove` on a non-existent lease answers **error**
  (`No lease was found for client identifier: …`).
- **Two alerts that look like the same one and are not.** In Query Logs, the
  "the app is missing" one ends in "…from the Apps section." when "Query" fires
  it and **does not** when "Export" does (logs.js:391 vs 614). Copying one into
  both places changes a text.
- **The last page is asked for with `pageNumber=-1`**: the server resolves it.
  That is what the "Last" link of Query Logs does (logs.js:589), verified
  against the reference instance.
- **The `ts` cache-buster goes on only two of the six downloads**: the settings
  backup (main.js:3100) and `logs/download` (logs.js:196). `logs/export`,
  `zones/export`, `allowed/export` and `blocked/export` **do not carry it**. The
  server ignores it, but the URL that gets opened is not the same.
- **A form filter can live in `localStorage`**: "Logs Per Page" is stored under
  the key `optQueryLogsEntriesPerPage` and re-read on every reset (logs.js:23-26
  and 63-65). Careful: the form's default value is **10** and the server's is
  **25** (`WebServiceLogsApi.cs:162`); the form's wins because upstream always
  sends the parameter.
- **`serializeTableData` decodes TWICE.** It applies `htmlDecode` to a value the
  browser had already decoded when parsing the HTML, so typing `&amp;` in a cell
  sends `&`. In React there is no intermediate HTML: replicating it would mean
  introducing the bug by hand, and that is not done.
- **A `set` can return less than its `get`, and what is missing has to be kept.**
  `admin/sso/set` does NOT bring `localGroups`: `WriteSsoConfig` only writes them
  with `includeGroups` and the `set` calls it with `false`
  (WebServiceAuthApi.cs:1790). Upstream survives because it stored them in a
  global variable when doing the `get`. Reloading the form with the save
  response without keeping them leaves the group-map dropdowns empty.
- **A secret can come back MASKED and has to be sent back that way.**
  `admin/sso/get` returns `ssoClientSecret: "************"` as soon as one is
  stored, and `SetSsoConfig` ignores that exact value
  (WebServiceAuthApi.cs:1738). It is what allows saving the form without typing
  the secret again: clearing the field "because it looks like filler" would
  delete the real secret.
- **The same action can send different parameters depending on where it is
  fired from.** `admin/sessions/delete` ALWAYS travels with `node` from the
  Sessions tab (the primary node if the session is an API token, the chosen node
  in any other case) and **with no `node` at all** from the user details modal
  unless it is an API token (auth.js:1050 vs 1382).
- **A checkbox can change the ENDPOINT, not a parameter.** The cluster's "Force
  Remove Node" picks between `primary/deleteSecondary` and
  `primary/removeSecondary`; "Force Leave" and "Force Delete" in the same block
  really are parameters. They cannot be made uniform.
- **Deleting something that does not exist does NOT always answer `ok`.**
  `admin/sessions/delete` with an invented partial token answers `error` with
  "No such active session was found for partial token: …". Checked live against
  a v15.4; it is the exception to the rule noted above.
- **The group list depends on the endpoint that serves it.**
  `admin/permissions/get?includeUsersAndGroups=true` includes `Everyone` and
  `admin/groups/list` does not; `admin/sso/get?includeGroups=true` excludes it on
  purpose (WebServiceAuthApi.cs:383). Three group lists, three contents.
- **Two sibling endpoints can return different shapes of the same object.**
  `admin/groups/create` answers `{name, description}` and `admin/groups/set`
  also answers `members`. Same with the user: `users/get` brings `groups` (all
  the server's), `users/set` does not bring it even though it does bring
  `memberOfGroups` and `sessions`, and `users/list` and `users/create` bring
  none of the three. Checked live.
- **Half the response disappears when the cluster is not initialised.**
  `admin/cluster/state` on a standalone server is THREE fields: `version`,
  `dnsServerDomain` and `clusterInitialized`. `clusterDomain`, the four
  intervals and `clusterNodes` only exist with a cluster
  (WebServiceClusterApi.cs:60-75). And within a node, `upSince`, `lastSeen` and
  `configLastSynced` are **omitted** when they hold `default`, they do not
  arrive as `null`.
- **The cluster's "Quick Add" compares by SUBSTRING.** `cluster.js:30` uses
  `existingList.indexOf(ip) < 0`, so with `10.0.0.10` already in the list the IP
  `10.0.0.1` is never added. It is a bug of theirs and it is replicated: what
  the code does is copied, not what it looks like it wants to do.
- **A success alert dismisses itself after 5 seconds.** `showAlert`
  (common.js:212) schedules a `hideAlert` for `success` alerts and only for
  those. It is replicated here.
- **A whole section may filter NOTHING by permission.** Inside Administration,
  upstream checks `Administration.canView` to show or hide the section
  (main.js:165 and 240) and from there shows every button, letting the server
  reject. Adding client-side gating there would be adding behaviour, not
  protecting it.
- **Asymmetric permissions, the concrete Administration case**:
  `permissions/set` and `sso/set` ask for `Administration.canDelete`, not
  `canModify` (WebServiceAuthApi.cs:1533 and 1692). In the cluster, nearly
  everything asks for `canDelete` —including `init`, `initJoin` and `promote`—
  but `setOptions`, `resync`, `updatePrimary` and `updateIpAddress` ask for
  `canModify`.
- **`zones/list` OMITS `dnssecStatus` and `hasDnssecPrivateKeys` on Catalog and
  Forwarder zones**, and the Catalog also omits `catalog`. They are types that
  cannot be signed, so the server does not even write the fields. Declaring them
  required lies about half the list and in TypeScript it shows late.
- **The same table calls the same column differently.** In
  `zones/permissions/get`, a user permission brings `username` and a group one
  brings `name`. Treating them as the same shape leaves half the table blank.
- **`records/delete` has no branch for CNAME, DNAME, SOA or APP**: all four fall
  to the `default`, which only sends `rdata` if it exists — and it exists for
  none of them. The server receives zone+domain+type and nothing else. And
  **deleting an NS does not send `glue`, but disabling it does**: same pair of
  actions, different set of parameters.
- **Disabling a record reads the expiry TTL FROM THE MODAL, not from the row**
  (`updateRecordState`, zone.js:6236). If the modal has never been opened, it
  sends the empty string; if it was opened, it sends whatever was left inside.
  It is an upstream bug: it is replicated, and that is why the records screen
  drags that value along.
- **A record filter starting with `*` looks for the literal wildcard**, it does
  not list everything: after converting the glob to a regex, `showEditZonePage`
  rewrites a leading `.*\.` to `\*\.`. It serves to find the `*.zone` record,
  which in DNS really is called that. It looks like a bug and it is not.
- **The name filter without a wildcard is EXACT**, not "contains": typing `www`
  does not find `www.sub`. And it lowercases what you typed but **not** the zone
  name.
- **`zones/create` is a POST with the parameters in the QUERY**: the body is
  reserved for the optional zone file (`fileImportZone`). Without a file,
  upstream sends a POST with no body at all.
- **`zones/import` has TWO ways of sending the file**: uploading it goes as
  multipart and pasting it into the textarea goes as **raw plain text** with
  `Content-Type: text/plain`. The server tells them apart by that type.
- **The bulk zone delete uses the SAME endpoint** with the parameter in plural
  (`zones=`, comma-separated) and returns `deleted` and `failed`. When some
  fail, the alert is NOT an error: it is a `warning` counting how many.
- **The pagination window slides backwards on reaching the end**: on the last
  page the last ten are visible, not just one. And the last is asked for with
  `pageNumber=-1`: the server resolves it.
- **In the zone options, six empty lists travel as the string `"false"` and two
  do NOT**: `primaryNameServerAddresses` and `queryAccessNetworkACL` travel
  empty as they are. It is not symmetry; it is what `saveZoneOptions` does.
- **A zone that is a member of a catalog inherits its options**, and that
  governs the whole interface of `modalZoneOptions`: if the catalog does not let
  it override a section, that tab DISAPPEARS; if it does, it appears editable;
  and if a secondary catalog administers it as well, it appears read-only.
- **The tab that comes up open in the zone options is not the first**: on a
  Catalog it is "Query Access", and on a Primary it depends on whether there are
  catalogs available.
- **`convertZone` offers only three destinations** —Primary, Forwarder and
  Catalog— and which of them are enabled depends on the source through a table
  that follows from nothing: a Primary can only go to Forwarder.
- **The year has to be padded to four digits.** `0001-01-01T00:00:00` is .NET's
  `default(DateTime)` and turns up on every unused record; without padding,
  `getFullYear()` gives "1-01-01", which is not what moment writes.
- **In "Add Zone", the Catalog type shows NOTHING**: it has no branch in the
  visibility `switch`, so only the name and the type remain.
- **"Secondary ROOT Zone" is not a type**: it is a Secondary with the root
  server addresses preloaded, `zoneTransferProtocol=Tcp` and `validateZone=true`.
  The type that travels is `Secondary`.
- **The labels and the values of the DNSSEC dropdowns do not match**: you see
  "SHA256 (default)" and `SHA256` travels; you see "Ed25519 (default)" and
  `ED25519` travels in UPPERCASE.
- **In the DNSSEC properties, `isRetiring` switches off every action** of a key,
  and the automatic rollover only exists for ZSKs.

## How the code is written

- **Client**: always `apiRequest` from `src/api/client.ts`. Paths **relative and
  without a leading slash** (`'zones/list'`), because the server honours
  `X-Forwarded-Prefix`.
- **One `src/api/<family>.ts` file per endpoint family**, with its types. It
  should return data that is already usable, and `null` or an empty list on
  failure — but only where an empty result and a failure cannot be confused. If
  the screen would draw them the same, return the whole `ApiOutcome`: saying
  "no queries for this period" when the call never arrived is worse than an
  error.
- **Primitives** in `src/ui/`: `Button`, `Alert`, `Field`/`LabeledInput`,
  `Dialog`. Do not invent loose buttons or fields.
- **Colours always by token** (`var(--acc)`, `var(--ink)`…). Not one `#hex`
  outside `src/theme/tokens.css`.
- **One CSS module per component** (`X.module.css`).
- **Spacing, type and radii by token too.** In a `*.module.css` you do not write
  a px that is not one of the tokens in `theme/tokens.css`. A loose value is
  future drift: that is how the console reached 13 text sizes and 25 paddings.
- **A single theme, the dark one.** There is no theme picker.
- **Everything is in ENGLISH** — the interface, the code, the comments and the
  tests. The console is `lang="en"` and the destination is a pull request
  upstream.
- **No `BrowserRouter`**: the server's only `MapFallback` is `/api/{*path}`.
- **No CDN and no fonts in `data:`**: the server's CSP does not declare
  `font-src`. Images in `data:` are fine (`img-src 'self' data:`).

## Tests

- `npm test` — vitest. **Do not run `npm run build`** if other agents are
  working: it writes into `../www` and you would step on each other.
- Every screen needs tests for: **the literal alert texts**, the **validation
  order**, which endpoint is called and with what body, and the behaviour with
  empty data.
- Query by label (`getByLabelText`), not by class.
- **Do not assume a call is the first one**: find it.
  `spy.mock.calls.find(c => c[0] === 'zones/list')`.
- With fake clocks, `findBy*` does not work: use
  `vi.useFakeTimers({ shouldAdvanceTime: true })` and
  `userEvent.setup({ delay: null })`.
- **No apostrophes in a test description written with single quotes.** "the
  server's failure" inside `it('…')` does not parse, and it takes the whole file
  with it. Reword it: "the failure from the server".

## Deliberate deviations from upstream behaviour

The rule is "zero functionality", but there are three exceptions, **decided and
written down**. If you find a fourth, do not introduce it on your own: report it.

1. **A single theme, the dark one** (Adrián's decision). The "Change Theme"
   modal and its menu entry disappear. It is the only one that *removes*
   something.
2. **Settings jumps to the sub-tab of the invalid field.** Upstream focuses a
   hidden input and the user sees nothing; with one panel mounted at a time,
   without that jump the alert would be impossible to resolve.
3. **The "Enable DNS-over-HTTP/3" checkbox re-enables itself.** In upstream it
   stays dead until the page is reloaded because nothing re-evaluates its state:
   that is a bug of theirs, and replicating it would mean introducing the fault
   on purpose.

## Closing

When you finish, write down which endpoints you covered and **any upstream
behaviour you discovered that was not already noted**. That last part is the
most valuable thing you can contribute.
