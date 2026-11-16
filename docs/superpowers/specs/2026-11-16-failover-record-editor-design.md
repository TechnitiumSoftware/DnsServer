# App-owned Failover backend editor

The user wants individual input rows instead of JSON, enable/disable for each backend IP, and explicitly requires apps to supply their own UI components. No Failover UI or record schema belongs in the console.

## Design

Add an optional `IDnsAppRecordEditor` interface with a self-contained HTML document. The Apps API exposes it as `recordDataEditor`. The existing APP modal hosts it in a sandboxed iframe, initializes it through a private MessageChannel, and requests serialized data before add/update or switching to raw editing. The console knows neither the app class nor its fields. Apps without a component retain the existing raw editor.

Failover embeds its own HTML/CSS/JavaScript component. It supplies Primary, Secondary, and Server Down rows, per-IP Enabled controls, health-check name/URL and TXT status fields. Existing string entries remain enabled; objects with `address` and optional `enabled` carry per-entry state. All address paths skip disabled entries before parsing, monitoring, or answering. Preserve unknown properties; unsupported JSON remains in raw mode.

## Approaches

The user's explicit choice is app-owned UI injection. A hardcoded console form was rejected. A shared field-schema renderer was considered but does not give apps ownership of custom components. Isolated app-owned HTML supports that ownership while preserving the host's authentication and existing save APIs.

## Constraints

No runtime dependencies, CNAME changes, global configuration editor, or deployment. The iframe cannot access console credentials/DOM/storage or fetch external assets. Save failures must not submit stale data. Document the protocol for other apps. Updated Failover binaries require the updated server interface. Existing DNS caches and shared health monitors retain their normal lifetime.
