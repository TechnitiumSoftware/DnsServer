# Community DNS App Repositories

DNS Server admins can add any HTTPS URL as a "Community" DNS App repository from the Apps &rarr; Community tab, giving apps that aren't accepted into the official DNS App Store (for example because they need hardware/infrastructure the maintainer can't test against — see [issue #2058](https://github.com/TechnitiumSoftware/DnsServer/issues/2058)) a distribution path of their own.

This document covers both sides: admins who want to **install** someone else's community app, and authors who want to **publish** one. For the admin-facing API itself (`apps/repositories/add`, `apps/repositories/list`, `apps/repositories/remove`), see `APIDOCS.md`.

## Installing someone else's community app

There's no central index or directory of community repositories — this is a decentralized, ad-hoc distribution model, not a curated store like the official DNS App Store. To install an app someone else published:

1. Get the repository's manifest URL directly from the app author — their project's README, GitHub repo, an issue/PR discussion, or wherever they've shared it (Technitium community forums/Discord/Reddit, etc.).
2. In the DNS Server web console, go to Apps &rarr; Community, and add that URL as a repository (give it any display name you like).
3. If the app has a version compatible with your server, it shows up in the Community tab's app list with an Install button.

Since nothing here is vetted or reviewed, only add repository URLs from authors/sources you trust — an installed app runs as native code inside the DNS server process. See "No checksum or signature verification" below.

## Publishing your own community app

The rest of this document is for **app authors** who want their app installable this way.

### What you need to host

A repository is just a static JSON file served over HTTPS — a GitHub raw URL, a GitHub Pages page, a gist, anything that returns the right JSON. There's no submission process and no approval; the admin who wants your app pastes your manifest URL into their server.

The manifest is the exact same schema the official DNS App Store uses: either a JSON array of app entries, or a single app entry as a bare JSON object (useful if your repo only ever serves one app).

```json
[
  {
    "name": "Example Community App",
    "description": "One-line description shown in the Community tab's app list.",
    "versions": [
      {
        "serverVersion": "15.0",
        "version": "1.0.0",
        "url": "https://github.com/you/your-app/releases/download/v1.0.0/YourApp-1.0.0.zip",
        "size": "12.3 KB"
      },
      {
        "serverVersion": "15.4",
        "version": "1.1.0",
        "url": "https://github.com/you/your-app/releases/download/v1.1.0/YourApp-1.1.0.zip",
        "size": "13.1 KB"
      }
    ]
  },
  {
    "name": "Another Community App",
    "description": "A second, unrelated app served from the same repository.",
    "versions": [
      {
        "serverVersion": "15.0",
        "version": "2.3.0",
        "url": "https://github.com/someone-else/another-app/releases/download/v2.3.0/AnotherApp-2.3.0.zip",
        "size": "8.7 KB"
      }
    ]
  }
]
```

A single repository can serve as many app entries as you like — one repo isn't limited to one app. Each entry is looked up and resolved independently by `name`, so unrelated apps (even from different authors) can share one manifest URL.

Field notes:

- **`name`** must exactly match the app name your app registers with the DNS Server (the name shown in the Installed Apps list). The server uses this string as the install/uninstall/update key — a mismatch means "installed" detection and updates silently won't work.
- **`description`** is plain text (rendered HTML-encoded), shown in the Community tab.
- **`versions`** is a list, not a single object, even if you only ever publish one version. Each entry:
  - **`serverVersion`**: the minimum DNS Server version this build requires.
  - **`version`**: your app's version string.
  - **`url`**: direct HTTPS download link to the `.zip` package (same package format as a manual/sideloaded app install — same as what you'd upload via Apps &rarr; Install from Zip).
  - **`size`**: a human-readable size string (e.g. `"50.02 KB"`). It's display-only, not validated against the actual download.
- When resolving which version to offer, the server picks the entry with the **highest `serverVersion` that is still `<=` the running server's version**. This lets you publish multiple builds targeting different server compatibility ranges in one manifest, same as the official store does.
- Any entry the server can't parse (missing fields, bad JSON) is skipped without breaking the rest of your manifest or any other configured repository.

### No checksum or signature verification

Same trust model as the official store: the server fetches your `url` and installs whatever `.zip` is there over HTTPS. There is no checksum/signature check on the package. An admin adding your repository URL is trusting your HTTPS endpoint (and its release infrastructure) directly — say so in your own README if you use a mutable "latest" URL versus a pinned release tag.

### Writing the app itself

This repository's manifest format only covers *distribution*. For the actual app implementation (the interfaces to implement, how config/records/query logging hooks work), the `DnsServerCore.ApplicationCommon` project's interfaces (`IDnsApplication`, `IDnsQueryLogger`, `IDnsAuthoritativeRequestHandler`, `IDnsRequestBlockingHandler`, `IDnsAppRecordRequestHandler`, `IDnsPostProcessor`, etc.) are the contract, and the `Apps/` folder in this repository has working, real examples (e.g. `Apps/DnsBlockListApp`, `Apps/QueryLogsSqliteApp`) to copy patterns from.
