# NxDomain App

A DNS App for Technitium DNS Server that blocks configured domain names by returning **NXDOMAIN**.

## Overview

- **Flat blocklist** – block specific domains
- **Subdomain matching** – blocking `example.com` also blocks `www.example.com`
- **TXT reporting** – optional metadata in TXT responses
- **Execution priority** – controlled by `appPreference`

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAuthoritativeRequestHandler`, `IDnsApplicationPreference`
- Runs in the authoritative request path.

## Configuration

`dnsApp.config` contains exactly these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | number | `20` | App execution order (lower runs earlier). |
| `enableBlocking` | boolean | required | Enables or disables blocking. |
| `allowTxtBlockingReport` | boolean | required | Enables TXT blocking reports and EDNS error text. |
| `blocked` | string[] | required | Domain names to block. A blocked domain applies to the exact name and its subdomains. |

### Example

```json
{
  "appPreference": 20,
  "enableBlocking": true,
  "allowTxtBlockingReport": true,
  "blocked": [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com"
  ]
}
```

## Runtime behavior

1. Checks the queried domain against the `blocked` list.
2. If the domain or any parent domain is blocked, the app returns NXDOMAIN.
3. If the query type is TXT and `allowTxtBlockingReport` is enabled, it returns a TXT response with blocking metadata.
4. If EDNS is present and TXT reporting is enabled, it includes an Extended DNS Error.

## Risks / operational notes

- Blocking is global; there are no per-client or per-network policies.
- Blocking a parent domain blocks all subdomains.
- TXT reports may reveal that a domain was blocked.

## Troubleshooting

- Confirm `enableBlocking` is `true`.
- Confirm the domain is present in `blocked` or is a subdomain of a blocked name.
- Verify `allowTxtBlockingReport` if TXT responses are expected.
