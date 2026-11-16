# App-owned record editors

An APP record handler can also implement `IDnsAppRecordEditor`. Its optional `ApplicationRecordDataEditor` property returns a complete HTML document containing the app's own markup, inline CSS, and inline JavaScript. Embed the document as an assembly resource so it ships with the app. See [Failover's component](FailoverApp/record-editor.html) and [resource declaration](FailoverApp/FailoverApp.csproj).

The Apps API exposes the document as `dnsApps[].recordDataEditor`. The console discovers it by the selected app and handler; it contains no app-specific fields or class checks. Apps without an editor retain the raw record-data textarea. Existing record add/update APIs and permissions remain in use.

## Version 1 protocol

The console loads the component in an iframe and sends one window message:

```js
{
    type: "dns-app-record-editor:init",
    version: 1,
    data: "the existing record data, unchanged",
    theme: "light" // or "dark", "amber"
}
```

The message transfers a `MessagePort` as `event.ports[0]`. Check `event.source === parent`, the message type, and protocol version before accepting it. All subsequent communication uses that port, not global window messages. The theme is the console's theme at editor load time.

Component → console:

| Message | Purpose |
| --- | --- |
| `{type: "ready"}` | Initial data has been loaded into the component. |
| `{type: "unsupported", error: "explanation"}` | Cannot edit this input; show the original raw data without modifying it. |
| `{type: "resize", height: 500}` | Request a height in pixels; the console clamps it to 120–1000. Taller components scroll. |
| `{type: "save", requestId, data: "serialized record"}` | Successful response to a save request. |
| `{type: "save", requestId, error: "validation message"}` | Reject the save and explain how to correct the input. |

Console → component:

```js
{ type: "save", requestId: 1 }
```

Read the current controls and validate them before replying with the same `requestId`. The console waits up to five seconds, then refuses to save if the component does not respond. This request is also used when switching to raw mode, preserving unsaved form edits. Switching back reloads the component using the current raw text. Closing the record or selecting another app closes the port and cancels pending saves.

Preserve unknown record properties whenever possible. If a record cannot be represented without data loss, send `unsupported`. Use DOM text/value properties for user data, not HTML interpolation. The console never parses the app's record format.

## Isolation and packaging

The iframe has `sandbox="allow-scripts"` without same-origin access. Its content security policy permits inline scripts/styles and data images, and blocks network resources, connections, form submissions, and base URL overrides. Bundle any required libraries inline. The component receives record data and theme, never API credentials or access to the parent document. It does not call save APIs itself.

Deploy an app using this new interface together with a server that includes the interface and host support. Older apps do not need changes. The Failover address editor applies only to `Failover.Address`; CNAME records continue to use their existing raw editor.

## Focused checks

With Node and the project's .NET 10 / sibling TechnitiumLibrary build prerequisites installed:

```sh
node --test tests/failover-editor.test.cjs
dotnet run --project tests/FailoverApp.Tests -c Release
```

The browser test uses Playwright as an external test tool, without adding a runtime dependency. Set `PLAYWRIGHT_MODULE` to its module path and optionally `CHROME_PATH` to an installed Chrome executable, then run `node tests/app-record-editor.browser.cjs`.
