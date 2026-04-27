# No Data App

A DNS App for Technitium DNS Server that returns **NOERROR / NODATA** for selected query types using APP record data.

## Overview

- **APP-record driven** – no root-level `dnsApp.config` keys
- **Blocked query types** – driven by `blockedTypes` in APP record JSON
- **NODATA responses** – returns NOERROR with an empty answer section

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

### APP record JSON

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `blockedTypes` | string[] | yes | DNS record types to return NODATA for (for example `A`, `AAAA`, `ANY`). |

### Example

```json
{
  "blockedTypes": ["A", "AAAA", "ANY"]
}
```

## Runtime behavior

1. The query name must match the APP record name, unless the APP record name is a wildcard.
2. The app parses `appRecordData` as JSON.
3. If the question type is in `blockedTypes`, or `ANY` is present, the app returns NOERROR with no answers.
4. Otherwise, it returns no response and the query continues through normal resolution.

## Risks / operational notes

- NODATA can be cached negatively by clients and recursive resolvers.
- This app suppresses responses for selected types; use carefully if clients expect those records.

## Troubleshooting

- Confirm the APP record data contains valid JSON.
- Confirm `blockedTypes` includes the requested type.
- Confirm the query name matches the APP record name or wildcard rule.