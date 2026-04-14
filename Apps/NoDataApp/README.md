# No Data App

## Summary

A DNS App for Technitium DNS Server that returns a **NOERROR / NODATA** response for selected query types.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as: an APP-record request handler (answers are provided from the APP record context).

## Configuration

This app is **APP-record driven**.

- `dnsApp.config` is not used by this app.
- Configuration is provided via the **APP record data** (JSON) in a zone.

### APP record JSON

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `blockedTypes` | string[] | Yes | DNS RR types to return NODATA for. Values are parsed as `DnsResourceRecordType` (e.g. `A`, `AAAA`, `MX`, `TXT`, `ANY`). |

### Example

```json
{
  "blockedTypes": [
    "A",
    "AAAA",
    "ANY"
  ]
}
```

## Runtime behavior

- The request name must match the APP record name **exactly** (or match wildcard APP record name patterns as supported by the DNS app runtime).
- If the request type is in `blockedTypes` (or `ANY` is present), the app returns NOERROR with an empty answer section.
- Other query types pass through unmatched and receive no response from this app.

## Risks / operational notes

- NODATA responses are cached with negative cache TTL; ensure this is intentional.
- Clients expecting certain record types will appear to receive no data (not NXDOMAIN).
- Can mask configuration errors; verify intent is correct.