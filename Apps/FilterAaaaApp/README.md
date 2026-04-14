# Filter AAAA App

A DNS App for Technitium DNS Server that filters AAAA responses when an A record also exists.

## Overview

- **Post-processor** – modifies responses after core resolution
- **AAAA filtering** – returns NODATA when A records exist for the same name
- **Bypass support** – skip local zones, networks, or domains

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsPostProcessor`
- Runs as a post-processor.

## Configuration

`dnsApp.config` contains these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableFilterAaaa` | boolean | `false` | Enables filtering. |
| `defaultTtl` | number | `30` | SOA TTL used for NODATA responses. |
| `bypassLocalZones` | boolean | `false` | Do not modify authoritative answers. |
| `bypassNetworks` | string[] | `[]` | Client networks excluded from filtering. |
| `bypassDomains` | string[] | `[]` | Domain names excluded from filtering. |
| `filterDomains` | string[] | `[]` | Domains eligible for filtering; empty means all domains. |

### Example

```json
{
  "enableFilterAaaa": true,
  "defaultTtl": 30,
  "bypassLocalZones": false,
  "bypassNetworks": [],
  "bypassDomains": ["ipv6.example.com"],
  "filterDomains": []
}
```

## Runtime behavior

1. Only acts on AAAA responses with `NoError`.
2. Skips signed responses when DNSSEC is in use.
3. Bypasses configured networks/domains and local zones when set.
4. If the same name has an A record, returns NODATA.

## Risks / operational notes

- Can break IPv6-only access if misconfigured.
- Adds an extra A lookup per filtered query.
- NODATA responses are cached negatively.
