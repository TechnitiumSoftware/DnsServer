# NxDomain Override App

## Summary

A DNS App for Technitium DNS Server that overrides **NXDOMAIN** responses for **A/AAAA** queries by returning configured IP addresses.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsPostProcessor`
- Runs as: a post-processor (operates on DNS responses after core resolution).

## Configuration

The app is configured using `dnsApp.config` (JSON).

### Root configuration options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableOverride` | boolean | `true` | Enables overriding NXDOMAIN responses. |
| `defaultTtl` | number | `300` | TTL (seconds) used for overridden A/AAAA answers. |
| `domainSetMap` | object | `{}` | Map of domain name to list of set names. Use `"*"` as the catch-all entry. |
| `sets` | object[] | `[]` | Array of named address sets. |

### `domainSetMap`

`domainSetMap` maps a domain (or `"*"`) to one or more set names.

Notes:

- `"*"` applies when there is no more specific domain match.
- A domain entry applies to the exact name and its subdomains.

### `sets`

Each set is an object:

| Property | Type | Description |
| --- | --- | --- |
| `name` | string | Set name referenced by `domainSetMap`. |
| `addresses` | string[] | List of IP addresses to return (IPv4 and/or IPv6). |

## Example

```json
{
  "enableOverride": true,
  "defaultTtl": 300,
  "domainSetMap": {
    "*": ["set1"],
    "example.com": ["set1", "set2"]
  },
  "sets": [
    {
      "name": "set1",
      "addresses": ["192.168.10.1"]
    },
    {
      "name": "set2",
      "addresses": ["1.2.3.4", "5.6.7.8"]
    }
  ]
}