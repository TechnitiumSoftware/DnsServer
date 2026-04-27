# Advanced Forwarding App

A DNS App for Technitium DNS Server that performs conditional forwarding to configured upstream resolvers.

## Overview

- **Conditional forwarding** – route queries by domain and client network
- **Multiple forwarders** – define reusable upstream resolvers
- **Proxy support** – forwarders may use a proxy server definition
- **Group-based control** – forwarding rules are grouped by client network

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAuthoritativeRequestHandler`, `IDnsApplicationPreference`
- Runs in the authoritative request path when forwarding is enabled.

## Configuration

`dnsApp.config` contains these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | number | `200` | App execution order. |
| `enableForwarding` | boolean | `true` | Master switch for forwarding. |
| `proxyServers` | array | `[]` | Proxy server definitions used by forwarders. |
| `forwarders` | array | `[]` | Forwarder definitions. |
| `networkGroupMap` | object | required | Maps client networks to group names. |
| `groups` | array | required | Forwarding groups and their domain/forwarder mappings. |

### Example

```json
{
  "appPreference": 200,
  "enableForwarding": true,
  "proxyServers": [
    {
      "name": "local-proxy",
      "type": "socks5",
      "proxyAddress": "localhost",
      "proxyPort": 1080,
      "proxyUsername": null,
      "proxyPassword": null
    }
  ],
  "forwarders": [
    {
      "name": "quad9-doh",
      "proxy": null,
      "dnssecValidation": true,
      "forwarderProtocol": "Https",
      "forwarderAddresses": ["https://dns.quad9.net/dns-query (9.9.9.9)"]
    }
  ],
  "networkGroupMap": {
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "everyone",
      "enableForwarding": true,
      "forwardings": [
        {
          "forwarders": ["quad9-doh"],
          "domains": ["*"]
        }
      ]
    }
  ]
}
```

## Runtime behavior

1. The app selects a client group based on `networkGroupMap`.
2. It checks whether forwarding is enabled for the selected group.
3. It matches the queried domain against the group's forwarding rules.
4. It returns custom FWD records for matching forwarders.

## Risks / operational notes

- Overlapping forwarding rules can be hard to reason about.
- A bad upstream or proxy definition can break resolution for selected domains.
- Keep network group mappings explicit to avoid unintended routing.

## Troubleshooting

- Confirm the client IP matches a group in `networkGroupMap`.
- Confirm the group has `enableForwarding: true`.
- Confirm the query domain matches one of the group's `domains` entries.
