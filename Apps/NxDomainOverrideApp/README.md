# NxDomain Override App

A DNS App for Technitium DNS Server that overrides NXDOMAIN responses for A/AAAA queries using configured IP address sets.

## Overview

- **Domain-to-set mapping** – map domains to named sets
- **Catch-all support** – use `*` for default mappings
- **NXDOMAIN override** – only operates when the upstream result is NXDOMAIN
- **A/AAAA only** – returns A or AAAA answers based on the requested type

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsPostProcessor`
- Runs after resolution and only when the response is NXDOMAIN.

## Configuration

`dnsApp.config` contains these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableOverride` | boolean | `true` | Enables override behavior. |
| `defaultTtl` | number | `300` | TTL for returned answers. |
| `domainSetMap` | object | required | Maps domains (or `*`) to an array of set names. |
| `sets` | array | required | Array of named sets, each with `name` and `addresses`. |

### Example

```json
{
  "enableOverride": true,
  "defaultTtl": 300,
  "domainSetMap": {
    "*": ["set1"],
    "example.com": ["set1", "set2"]
  },
  "sets": [
    { "name": "set1", "addresses": ["192.168.10.1"] },
    { "name": "set2", "addresses": ["1.2.3.4", "5.6.7.8"] }
  ]
}
```

## Runtime behavior

1. The app only acts when the response code is NXDOMAIN.
2. The queried name is matched against `domainSetMap` (exact, wildcard-style `*.` parent matching, then `*`).
3. The matching set names are resolved against `sets`.
4. For A queries, IPv4 addresses are returned; for AAAA queries, IPv6 addresses are returned.
5. If the response is DNSSEC-aware or not an NXDOMAIN, the app leaves it unchanged.

## Risks / operational notes

- Only NXDOMAIN responses are overridden.
- If `domainSetMap` is too broad, many domains may resolve to the same address set.
- Mixed A/AAAA address lists should be intentional.

## Troubleshooting

- Confirm the upstream result is NXDOMAIN.
- Confirm the domain exists in `domainSetMap` or `*`.
- Confirm the set name exists in `sets`.