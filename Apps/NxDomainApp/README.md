# NxDomain App

A DNS App for Technitium DNS Server that blocks selected domains by returning **NXDOMAIN** based on a flat blocklist.

## Overview

The NxDomain App provides simple, fast domain blocking using a straightforward blocklist approach:

- **Flat domain blocklist** – Simple list of domain names to block
- **Subdomain matching** – A blocked domain blocks all its subdomains
- **TXT reporting** – Optional blocking metadata in TXT query responses
- **Execution priority** – Control when this app runs relative to other apps
- **No rules engine** – Minimal configuration for maximum performance

This app is ideal for administrators who need basic domain blocking without complex policies or per-client rules.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAuthoritativeRequestHandler`, `IDnsApplicationPreference`
- Runs as: an authoritative request handler (can serve blocking answers in the authoritative phase).

## Configuration

The app is configured using `dnsApp.config` (JSON).

### Root configuration options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | number | `0` | App execution preference/priority (lower runs earlier). |
| `enableBlocking` | boolean | `true` | Enables blocking behavior. |
| `allowTxtBlockingReport` | boolean | `false` | When `true`, include metadata in TXT query responses for blocked domains. |
| `blocked` | string[] | `[]` | List of domain names to block. A domain entry applies to the exact name and its subdomains. |

## Example

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

## How It Works

1. **Query Reception** – DNS server receives a query for a domain.

2. **Blocklist Check** – App checks if the queried domain (or parent domain) is in the `blocked` list using domain hierarchy matching.

3. **Block Decision**:
   - If found in blocklist: return NXDOMAIN response
   - If not found: allow query to proceed normally

4. **TXT Reporting** – If `allowTxtBlockingReport` is enabled and a TXT query is made for a blocked domain, include metadata about the block in the response.

5. **Priority Control** – The `appPreference` value determines execution order relative to other apps (lower = runs earlier).

## Use Cases

- **Basic domain filtering** – Block known malicious or unwanted domains
- **Corporate content filtering** – Simple blocklist for business networks
- **DNS sinkhole** – Return NXDOMAIN for compromised domains
- **Typosquatting protection** – Block common misspellings of corporate domains
- **ISP-level blocking** – Enforce basic content policies at DNS layer
- **IoT device filtering** – Block tracking/telemetry domains for specific devices

## Risks / Operational Notes

- **Silent blocking** – Clients receive NXDOMAIN without explanation; may confuse users
- **No granularity** – Cannot apply different policies per-client or per-network; use AdvancedBlockingApp for that
- **Subdomain assumption** – Blocking `example.com` also blocks `www.example.com`, `mail.example.com`, etc.; be careful with overly broad entries
- **Precedence** – Use `appPreference` to control when this app runs relative to other blocking apps
- **TXT overhead** – If `allowTxtBlockingReport` is enabled, each TXT query for blocked domains incurs extra processing

## Troubleshooting

### Domains not being blocked

**Symptoms:** A domain that should be blocked is resolving normally

**Diagnostic Steps:**

1. Verify the domain appears in the `blocked` array (case-insensitive match)
2. Check that `enableBlocking` is `true`
3. Confirm the domain matches exactly or is a parent of queried domain
4. Ensure no other app is overriding this app's blocking
5. Review app execution order (check `appPreference` against other blocking apps)

**Resolution:** Add the exact domain to the `blocked` list, or verify no higher-priority app is allowing it

### TXT reports not appearing

**Symptoms:** TXT query for a blocked domain doesn't return blocking info

**Diagnostic Steps:**

1. Verify `allowTxtBlockingReport` is set to `true`
2. Confirm the domain is actually in the `blocked` list
3. Check the client is actually requesting TXT records

**Resolution:** Ensure configuration is saved and app is reloaded after changes

### Performance impact

**Symptoms:** DNS queries slow down after enabling the app

**Diagnostic Steps:**

1. Review the size of the `blocked` list
2. Check `appPreference` – if too low, may run on every query
3. Monitor CPU/memory usage during high query volume

**Resolution:**

- Keep blocklist reasonably sized
- Adjust `appPreference` if necessary
- Consider AdvancedBlockingApp for per-client policies (more efficient for complex scenarios)

### App not loading

**Symptoms:** App appears disabled or throws errors in logs

**Diagnostic Steps:**

1. Verify `dnsApp.config` is valid JSON
2. Check that all required keys are present (at minimum: `appPreference`, `enableBlocking`, `allowTxtBlockingReport`, `blocked`)
3. Review DNS server application logs for parse errors

**Resolution:** Correct JSON syntax and ensure config is valid

## License

This application is part of the **Technitium DNS Server** project.

**License:** GNU General Public License v3.0 (GPL-3.0)

Copyright © 2025 Technitium

Full license text: https://www.gnu.org/licenses/gpl-3.0.html
