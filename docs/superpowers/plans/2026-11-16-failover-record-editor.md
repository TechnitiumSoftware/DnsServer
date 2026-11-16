# App-Owned Failover Record Editor Implementation Plan

**Goal:** Let apps inject their own record editor, and provide Failover backend IP rows with enable/disable.

**Architecture:** An optional app interface exposes embedded HTML through Apps metadata. The console hosts the component in an isolated iframe and uses a private MessageChannel to initialize it and await saves. Failover owns its markup, scripts, styles and data format.

**Tech Stack:** Existing jQuery/Bootstrap console, vanilla app component, C#/.NET 10, Node built-in tests; Playwright is an external test tool only.

**Spec:** `docs/superpowers/specs/2026-11-16-failover-record-editor-design.md`

## Review focus

No app names, class checks, or record fields in the host. Preserve raw/custom data and old apps. Exclude disabled IPs from IPv4, IPv6, TXT and server-down paths. Cancel pending saves on editor changes. Keep credentials outside app frames. Capture the latest edits before both save APIs.

## Tasks

- [x] Add regression checks and observe failures before implementation.
- [x] Add the optional editor interface, Apps API metadata and generic iframe host in `zone.js`/`index.html`.
- [x] Embed the app-owned component in `Apps/FailoverApp/record-editor.html`; centralize enabled-address parsing in `Address.cs`.
- [x] Document the extension protocol, JSON compatibility, behavior and deployment requirements.
- [x] Complete browser interaction checks, independent review and final verification.

## Validation record

- Node parsing/round-trip/IP validation tests pass.
- .NET Failover tests pass: resource packaging, enabled-address parsing, IPv4/IPv6 fallback, all-disabled behavior, TXT filtering.
- DnsServerCore Release build passes with zero warnings/errors.
- Test prerequisites were installed under `/tmp`, with no runtime dependencies added to the repository. The external TechnitiumLibrary Mail project needed an explicit reference to its existing core project for compilation; no library implementation was changed.
- Browser checks pass: injection under unrelated app/class names; a second custom UI with non-JSON data; sandbox isolation; per-IP edits; invalid IP/URL handling; raw mode round trips; add/update payloads; save cancellation; mobile controls.
- Independent review found malformed IPv6 URL fragments could pass validation. A failing regression reproduced it; the literal-character check fixed it and all tests pass.
- Final JavaScript syntax and git whitespace checks pass. A local running-server browser check passed: enable/save/reopen and disable/save/reopen against the real API. No production deployment or network failover drill was performed. Deploy the updated server and Failover app together.
