# Filter AAAA App

## Summary

A DNS App for Technitium DNS Server that selectively filters IPv6 AAAA record responses based on domain and network rules.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsPostProcessor`
- Runs as: a post-processor (operates on DNS responses after core resolution).

## Configuration

The app is configured using `dnsApp.config` (JSON).

### Root configuration options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableFilterAaaa` | boolean | `true` | Enables AAAA filtering. |
| `defaultTtl` | number | `30` | TTL (seconds) for SOA record in NODATA responses when AAAA records are filtered. |
| `bypassLocalZones` | boolean | `false` | When `true`, authoritative answers from local zones are passed through unmodified. |
| `bypassNetworks` | string[] | `[]` | List of client networks (CIDR notation) excluded from filtering. |
| `bypassDomains` | string[] | `[]` | List of domain names excluded from filtering. A domain entry applies to the exact name and its subdomains. |
| `filterDomains` | string[] | `[]` | List of domain names to filter. When empty, all domains are eligible (subject to bypass rules). |

## Runtime behavior

- Returns NODATA (NOERROR with SOA in authority section) for AAAA queries when A records exist for the same name.
- Only filters when configured domain and network conditions match.
- Skips authoritative answers if `bypassLocalZones` is `true`.
- Performs a direct A record lookup to determine if filtering should apply.
- DNSSEC-signed responses are never modified (detected by RRSIG records and `DnssecOk` flag).

## Risks / operational notes

- NODATA responses are cached (negative cache TTL); may cause applications to retry.
- IPv6-only domains will incorrectly appear unavailable; ensure `bypassDomains` or `filterDomains` rules are accurate.
- Can degrade connectivity for IPv6-first clients; use with caution.
- Each filtered query triggers an additional A record lookup; can impact performance on high-traffic servers.
- Interacts poorly with DNSSEC-signed zones; will bypass filtering if RRSIG records are present.

## Example

```json
{
  "enableFilterAaaa": true,
  "defaultTtl": 30,
  "bypassLocalZones": false,
  "bypassNetworks": [],
  "bypassDomains": [
    "ipv6.example.com"
  ],
  "filterDomains": []
}
```

**Behavior:**
- Enables global AAAA filtering.
- Uses 30-second TTL for NODATA responses.
- Bypasses filtering for `ipv6.example.com` and its subdomains.
- When `filterDomains` is empty, all other domains are eligible for filtering if they have A records.
