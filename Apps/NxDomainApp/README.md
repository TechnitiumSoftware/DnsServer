# NxDomain App

A DNS App for Technitium DNS Server that provides advanced non-existent domain (NXDOMAIN) handling with configurable response policies, including granular control over synthetic NXDOMAIN responses and DNS traffic classification.

This app extends the core DNS server's default NXDOMAIN behavior by intercepting queries that would normally result in NXDOMAIN responses and applying custom response policies based on configurable rules. It enables administrators to implement sophisticated DNS filtering, traffic analysis, and controlled denial strategies.

## Overview

The **NxDomain App** enhances Technitium DNS Server by providing policy-based control over NXDOMAIN responses. It operates as a request/response interceptor that evaluates DNS queries against configured rules and applies custom response behaviors.

**Key capabilities:**

- **Custom NXDOMAIN response policies** – Define how the server responds to non-existent domains
- **Domain pattern matching** – Use exact matches, wildcards, and regex patterns for domain classification
- **Conditional response manipulation** – Return synthetic responses, forward queries, or block based on policy
- **Query classification and logging** – Track and categorize NXDOMAIN patterns for analysis
- **Integration with core DNS pipeline** – Operates transparently within the DNS resolution flow

This app is valuable for administrators implementing DNS-based content filtering, threat intelligence integration, DNS sinkholing, or traffic analysis in enterprise, ISP, or security-focused environments.

## ⚠️ Important Warning: Interaction with Core DNS Resolution

This app intercepts DNS queries **before** and **after** core resolution logic. Incorrect configuration can cause:

- **Resolution failures** for legitimate domains
- **Unexpected response codes** that break client behavior
- **Performance degradation** due to excessive pattern matching
- **Conflicts with blocklist apps** or other DNS filtering plugins

**Decision framework:**

- **Option A**: Use this app for *custom NXDOMAIN policies* when you need granular control over non-existent domain responses
- **Option B**: Use core DNS blocklists or firewall rules for simple domain blocking

**Processing order:** This app evaluates queries during the `PostResolution` phase, meaning it acts on responses returned by upstream resolvers or authoritative zones. Configuration must account for this execution context.

## Installation

1. Open the Technitium DNS Server web console

2. Navigate to **Apps** in the main menu

3. Click **Install** or **Update** and select the NxDomain App package

4. Configure the app using the configuration file structure described below

## Configuration

The app is configured through a JSON configuration file named **`dnsApp.config`**.

The configuration structure consists of root-level settings and domain-specific rules organized into rule groups. All configuration is loaded at app initialization and can be reloaded without restarting the DNS server.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | Boolean | `true` | Enables or disables the entire app |
| `enableLogging` | Boolean | `false` | Enables detailed logging of NXDOMAIN evaluation and policy application |
| `logOnlyBlocked` | Boolean | `true` | When logging is enabled, log only blocked queries (reduces log volume) |
| `defaultAction` | String | `allow` | Default action when no rules match: `allow`, `block`, `nxdomain` |
| `rules` | Array | `[]` | Array of rule objects defining domain patterns and response policies |

### Rule Configuration

Each rule in the `rules` array defines a domain matching pattern and associated response policy.

#### Rule Object Properties

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | *(required)* | Descriptive name for the rule (used in logs) |
| `enabled` | Boolean | `true` | Enables or disables this specific rule |
| `description` | String | `""` | Optional human-readable description |
| `domain` | String | *(required)* | Domain pattern to match (supports wildcards and regex) |
| `patternType` | String | `wildcard` | Pattern matching type: `exact`, `wildcard`, `regex` |
| `action` | String | `nxdomain` | Response action: `nxdomain`, `block`, `allow`, `customResponse` |
| `customResponse` | Object | `null` | Custom DNS response configuration (if `action` is `customResponse`) |
| `priority` | Integer | `100` | Rule evaluation priority (lower values = higher priority) |

### Pattern Types

The app supports three pattern matching modes:

#### Exact Match

```json
{
  "domain": "example.com",
  "patternType": "exact"
}
```

Matches only `example.com` (case-insensitive).

#### Wildcard Match

```json
{
  "domain": "*.malicious.com",
  "patternType": "wildcard"
}
```

Supports `*` wildcard. Example matches: `subdomain.malicious.com`, `deep.subdomain.malicious.com`

#### Regex Match

```json
{
  "domain": "^.*\\.(tk|ml|ga)$",
  "patternType": "regex"
}
```

Uses .NET regular expression syntax. Example matches TLDs: `.tk`, `.ml`, `.ga`

### Action Types

#### `nxdomain`

Returns a standard NXDOMAIN response (RFC 8020 compliant).

```json
{
  "action": "nxdomain"
}
```

#### `block`

Drops the query silently (no response sent).

```json
{
  "action": "block"
}
```

**Warning:** Silent drops can cause client timeout delays. Use only when necessary.

#### `allow`

Allows the query to proceed with the original NXDOMAIN response.

```json
{
  "action": "allow"
}
```

#### `customResponse`

Returns a synthetic DNS response with custom IP addresses.

```json
{
  "action": "customResponse",
  "customResponse": {
    "ipv4": "0.0.0.0",
    "ipv6": "::",
    "ttl": 300
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `ipv4` | String | IPv4 address for A record response |
| `ipv6` | String | IPv6 address for AAAA record response |
| `ttl` | Integer | Time-to-live for synthetic response (seconds) |

## Example Configuration

````json
{
  "enabled": true,
  "enableLogging": true,
  "logOnlyBlocked": false,
  "defaultAction": "allow",
  "rules": [
    {
      "name": "Block Typo Domains",
      "enabled": true,
      "description": "Block common typosquatting domains",
      "domain": "*.examp1e.com",
      "patternType": "wildcard",
      "action": "nxdomain",
      "priority": 10
    },
    {
      "name": "Sinkhole Malicious TLDs",
      "enabled": true,
      "description": "Redirect suspicious TLDs to sinkhole",
      "domain": "^.*\\.(tk|ml|ga|cf|gq)$",
      "patternType": "regex",
      "action": "customResponse",
      "customResponse": {
        "ipv4": "0.0.0.0",
        "ipv6": "::",
        "ttl": 3600
      },
      "priority": 20
    },
    {
      "name": "Allow Internal Domain",
      "enabled": true,
      "description": "Allow internal domain NXDOMAIN responses",
      "domain": "*.internal.corp",
      "patternType": "wildcard",
      "action": "allow",
      "priority": 5
    },
    {
      "name": "Block Tracking Domains",
      "enabled": true,
      "description": "Silently drop tracking domain queries",
      "domain": "*.tracker-analytics.net",
      "patternType": "wildcard",
      "action": "block",
      "priority": 15
    }
  ]
}
````

## How It Works

The NxDomain App processes DNS queries through the following pipeline:

1. **Query Interception** – The app hooks into the DNS server's `PostResolution` phase, examining responses returned by upstream resolvers or authoritative zones

2. **NXDOMAIN Detection** – If the response code is NXDOMAIN, the app extracts the queried domain name and begins rule evaluation

3. **Rule Evaluation** – Rules are evaluated in priority order (lowest priority number first). The first matching rule determines the action

4. **Pattern Matching** – The queried domain is compared against the rule's domain pattern using the specified pattern type (exact, wildcard, or regex)

5. **Action Application** – The matched rule's action is applied:
   - **nxdomain**: Returns the original NXDOMAIN response
   - **block**: Suppresses the response (client timeout)
   - **allow**: Passes through the original response
   - **customResponse**: Replaces the NXDOMAIN with a synthetic A/AAAA response

6. **Logging** – If logging is enabled, the app records the query, matched rule, and action taken

7. **Response Return** – The modified (or original) response is returned to the client

## Use Cases

### DNS Sinkholing for Security Operations

Configure the app to redirect known malicious domains to a controlled sinkhole IP address, enabling monitoring and analysis of infected systems attempting DNS resolution to C2 infrastructure.

### Typosquatting Protection

Implement rules to detect and block common typosquatting patterns targeting corporate domains, preventing credential harvesting and phishing attacks.

### Traffic Analysis and Classification

Use logging to identify patterns in NXDOMAIN queries, revealing potential DGA (Domain Generation Algorithm) activity, DNS tunneling attempts, or misconfigured applications.

### Controlled NXDOMAIN for Split-Horizon DNS

Allow specific internal domains to return genuine NXDOMAIN responses while applying custom policies to external queries, supporting hybrid DNS architectures.

### ISP-Level DNS Filtering

Deploy custom NXDOMAIN policies to enforce acceptable use policies, parental controls, or regulatory compliance requirements across subscriber networks.

### Research and DNS Abuse Detection

Log and categorize NXDOMAIN queries matching suspicious TLDs or patterns to support threat intelligence gathering and DNS abuse research.

## Troubleshooting

### Rules Not Matching Expected Domains

**Symptoms:** Queries that should match a rule are not being processed

**Diagnostic steps:**

1. Enable logging: Set `enableLogging` to `true` and `logOnlyBlocked` to `false`

2. Review DNS server logs for pattern match attempts

3. Verify pattern syntax:
   - Wildcard patterns require `*.` prefix for subdomain matching
   - Regex patterns must use escaped characters (`\\.` for literal dots)
   - Exact matches are case-insensitive

4. Check rule priority: Lower priority numbers are evaluated first

5. Verify the query actually results in NXDOMAIN before the app processes it

**Resolution:** Adjust `patternType` and `domain` values, test regex patterns using .NET regex tools

### Custom Responses Not Working for IPv6

**Symptoms:** A records are returned, but AAAA queries fail

**Diagnostic steps:**

1. Verify `customResponse` object includes both `ipv4` and `ipv6` properties

2. Check client is actually requesting AAAA records (not all clients do)

3. Review logs for response type

**Resolution:** Ensure valid IPv6 address format in `ipv6` property (e.g., `::` or `::1`)

### Performance Degradation with Many Rules

**Symptoms:** DNS query response times increase significantly

**Diagnostic steps:**

1. Review number of rules and pattern types

2. Identify regex patterns with complex expressions

3. Monitor CPU usage during high query volume

4. Check rule priority ordering

**Resolution:**

- Use exact or wildcard patterns instead of regex when possible
- Optimize regex expressions for performance
- Prioritize frequently matched rules (lower priority numbers)
- Consider splitting rules across multiple app instances if supported

### Logging Not Producing Output

**Symptoms:** No log entries appear despite configuration

**Diagnostic steps:**

1. Verify `enableLogging` is set to `true`

2. Check `logOnlyBlocked` setting – if `true`, only blocked queries are logged

3. Confirm queries are actually matching rules

4. Review DNS server log level configuration

**Resolution:** Set `logOnlyBlocked` to `false` temporarily to verify logging mechanism is functional

### Conflicts with Other DNS Apps

**Symptoms:** Unexpected responses or app errors

**Diagnostic steps:**

1. Identify other installed apps that modify DNS responses

2. Review app execution order in Technitium DNS Server

3. Check for overlapping domain patterns in multiple apps

**Resolution:**

- Disable conflicting apps temporarily to isolate behavior
- Adjust rule priorities to control evaluation order
- Use `allow` action to explicitly bypass this app's processing for specific domains

## License

This application is part of the **Technitium DNS Server** project.

**License:** GNU General Public License v3.0 (GPL-3.0)

Copyright © 2024 Technitium

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Full license text: https://www.gnu.org/licenses/gpl-3.0.html