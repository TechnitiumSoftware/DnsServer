# Filter AAAA App

A DNS App for Technitium DNS Server that selectively filters IPv6 AAAA record responses based on configurable domain rules and network conditions.

This application filters AAAA (IPv6) records by returning NODATA responses when A (IPv4) records for the same domain are available. This allows clients with dual-stack internet connections to prefer IPv4 and use IPv6 only when a website has no IPv4 support. It provides fine-grained control to address scenarios where IPv6 connectivity is unreliable, misconfigured, or needs to be disabled for specific domains or client networks.

## Overview

The **Filter AAAA App** extends the core DNS server's response processing pipeline to conditionally suppress IPv6 address records (AAAA) in DNS responses. It operates transparently between the upstream resolution and the client response phase, allowing administrators to:

- **Enforce IPv4-only resolution** for specific domains or domain patterns
- **Apply filtering per client network** using CIDR-based subnet matching
- **Implement global or conditional AAAA filtering** without modifying zone files
- **Address broken IPv6 deployments** at the DNS layer without network reconfiguration
- **Return NODATA responses** instead of removing records, preserving DNS protocol semantics
- **Dual-stack preference control** to enforce IPv4-first resolution when both protocols are available

This app is particularly useful for managing dual-stack environments with inconsistent IPv6 support, enforcing policy-based protocol preferences, and troubleshooting connectivity issues caused by misconfigured IPv6 infrastructure.

## ⚠️ Important Warning: Core DNS Feature Overlap

This DNS application provides functionality that **overlaps with the built-in AAAA record filtering feature** available in Technitium DNS Server (version 8.0 and later).

### Decision Guidance

#### Option A: Use Core DNS Server Feature

Navigate to **DNS Settings > Optional Protocols** and enable:

- **Filter AAAA (IPv6) Records**
\
- **Filter AAAA On Networks** (specify client subnets)
- **Filter AAAA Exception Domains** (specify bypass patterns)

**Advantages:**

- Native integration with server core
- Lower processing overhead
- Centralized configuration
- No plugin dependency

#### Option B: Use This App

Install and configure this DNS App when you require:

- Domain-specific filtering rules beyond simple exceptions
- Per-network domain filtering logic
- Custom filtering logic or processing order control
- Independent plugin lifecycle management

> **Note:** Enabling both the core DNS feature and this app simultaneously may result in **redundant processing** or **conflicting behavior**. Choose one approach based on your operational requirements.

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and upload the app package
4. Configure the app using the JSON configuration structure documented below

## Configuration

The app is configured using a JSON file typically named **`dnsApp.config`** located in the app's installation directory.

The configuration structure supports both global and network-specific filtering rules with domain-level granularity.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableFilterAAAA` | Boolean | `false` | Enables AAAA filtering globally for all DNS queries processed by the app |
| `defaultTtl` | Integer | `30` | TTL (in seconds) for NODATA responses returned when AAAA records are filtered |
| `bypassLocalZones` | Boolean | `false` | When true, authoritative answers from local zones are passed through unmodified |
| `bypassNetworks` | Array | `[]` | List of client networks (CIDR notation) excluded from filtering |
| `bypassDomains` | Array | `[]` | List of domain names (including subdomains) excluded from filtering |
| `filterDomains` | Array | `[]` | List of domain names to filter; when empty, all domains are filtered |
| `enableFilterAAAAOnNetworks` | Boolean | `false` | *(Deprecated - use `bypassNetworks` instead)* Enables network-specific AAAA filtering |
| `filterAAAAOnNetworks` | Array | `[]` | *(Deprecated - use `bypassNetworks` instead)* Network-specific filtering policies |

## Example Configuration

```json
{
  "enableFilterAAAA": true,
  "defaultTtl": 30,
  "bypassLocalZones": false,
  "bypassNetworks": [
    "192.168.1.0/24"
  ],
  "bypassDomains": [
    "ipv6test.google.com",
    "ipv6.example.com"
  ],
  "filterDomains": []
}
```

**Operational Behavior:**

- AAAA filtering is **enabled globally**
- Clients from `192.168.1.0/24`: filtering is **bypassed** (full IPv6 resolution)
- Domains `ipv6test.google.com` and `ipv6.example.com` (including subdomains): filtering is **bypassed**
- `filterDomains` is empty: filtering applies to **all other domains**
- Filtered responses use TTL of **30 seconds**

## Domain Pattern Formats

The `bypassDomains` and `filterDomains` arrays support domain matching with automatic subdomain inclusion.

### Domain Match with Subdomains

```json
"bypassDomains": [
  "example.com"
]
```

**Matches:** `example.com`, `www.example.com`, `sub.domain.example.com`  
**Behavior:** All subdomains are automatically included

**Note:** Unlike wildcard patterns, domain entries automatically match both the exact domain and all its subdomains.

## How AAAA Filtering Works

The app is a **post-processor** that modifies DNS responses before they are sent to clients. It processes responses through the following pipeline:

1. **Response Interception**  
   App intercepts responses generated by the DNS server core before client delivery

2. **Filtering Criteria Evaluation**  
   Response is processed **only if all** of the following conditions are met:
   - Response code is `NoError` (not `NXDOMAIN`, `SERVFAIL`, or existing `NODATA`)
   - Query type is `AAAA`
   - Response contains at least one `AAAA` record
   - Request is not excluded by `bypassLocalZones`, `bypassNetworks`, or `bypassDomains`
   - Domain matches `filterDomains` (if specified) or `filterDomains` is empty

3. **A Record Lookup**  
   App performs an internal lookup for A records for the same domain name

4. **Filter Decision**  
   - **If A records exist:** AAAA filtering is applied
   - **If no A records exist:** Original response is returned unmodified (preserves IPv6-only functionality)

5. **NODATA Response Construction**  
   Filtered response is constructed containing:
   - All `CNAME` records from the original response
   - A `SOA` record (for negative caching)
   - **No AAAA records**
   - TTL set to `defaultTtl`

6. **Response Delivery**  
   Modified NODATA response is returned to the client

7. **Client Behavior**  
   Client receives NODATA, indicating no IPv6 addresses are available, and retries using A record lookup (IPv4)

**Critical behavior:** The app only filters AAAA records when corresponding A records exist, ensuring IPv6-only domains remain accessible.

## Use Cases

### ISP Customer Network with Broken IPv6

An ISP operates a dual-stack network where IPv6 connectivity is unreliable due to infrastructure upgrades. Enable global AAAA filtering for customer subnets while maintaining IPv6 resolution for internal monitoring tools.

### Enterprise Branch Office Migration

A company is migrating branch offices from IPv4-only to dual-stack. Use per-network filtering to disable IPv6 resolution at sites not yet migrated, while allowing corporate headquarters to resolve AAAA records normally.

### Troubleshooting IPv6 Connectivity Issues

Clients experience slow DNS timeouts due to broken IPv6 paths. Deploy AAAA filtering as a temporary mitigation while network teams diagnose routing or firewall issues, without modifying client configurations.

### Policy-Based Protocol Enforcement

Security policy requires certain internal applications to use IPv4-only communication paths. Configure domain-specific exceptions to force IPv4 resolution for sensitive services while allowing general IPv6 use.

### Testing IPv4 Fallback Behavior

QA teams need to verify application behavior when IPv6 is unavailable. Use AAAA filtering to simulate IPv6 absence at the DNS layer without reconfiguring network infrastructure.

### Public Wi-Fi Hotspot Networks

Public Wi-Fi networks with captive portals may have misconfigured IPv6 that causes connectivity failures. Enable AAAA filtering globally with exceptions for portal authentication domains.

## Troubleshooting

### Filtering Not Applied to Expected Clients

**Symptoms:** Clients still receive AAAA records despite configuration

**Diagnostic Steps:**

1. Verify `enableFilterAAAA` or `enableFilterAAAAOnNetworks` is set to `true`
2. Check client IP against `network` CIDR blocks in configuration
3. Review DNS server logs for filter decision messages
4. Confirm queried domain is **not** in `filterAAAAExceptionDomains`
5. Verify app is enabled in DNS Server Apps interface

**Configuration Check:**

```json
{
  "enableFilterAAAAOnNetworks": true,
  "filterAAAAOnNetworks": [
    {
      "network": "192.168.1.0/24",
      "enableFilterAAAA": true
    }
  ]
}
```

### Exception Domains Not Working

**Symptoms:** AAAA records are filtered for domains listed in exceptions

**Diagnostic Steps:**

1. Verify domain pattern syntax (exact match vs wildcard)
2. Check for typos in domain names
3. Confirm domain casing (matching is case-insensitive but verify consistency)
4. Review network matching order (first match wins)
5. Test with explicit logging enabled

**Example Correct Exception Format:**

```json
"filterAAAAExceptionDomains": [
  "ipv6.google.com",
  "*.ipv6test.net"
]
```

### Global Filtering Overrides Network Rules

**Symptoms:** Network-specific rules are ignored

**Resolution:**

Ensure `enableFilterAAAAOnNetworks` is set to `true` and network rules are properly formatted:

```json
{
  "enableFilterAAAA": false,
  "enableFilterAAAAOnNetworks": true,
  "filterAAAAOnNetworks": [
    {
      "network": "10.0.0.0/8",
      "enableFilterAAAA": true
    }
  ]
}
```

**Processing Order:**

- Network-specific rules take precedence when `enableFilterAAAAOnNetworks` is enabled
- Global `enableFilterAAAA` is fallback only

### IPv6 Clients Not Matched

**Symptoms:** IPv6 clients do not match expected network rules

**Resolution:**

Use correct IPv6 CIDR notation:

```json
{
  "network": "2001:db8::/32",
  "enableFilterAAAA": true
}
```

For all IPv6 clients, use:

```json
{
  "network": "::/0",
  "enableFilterAAAA": true
}
```

### App Not Loaded After Installation

**Symptoms:** Configuration changes have no effect

**Diagnostic Steps:**

1. Navigate to **Apps** in web console
2. Verify app status is **Enabled**
3. Check DNS Server logs for app initialization errors
4. Restart DNS Server service
5. Verify `dnsApp.config` file is valid JSON

**Log Review:**

Check DNS Server logs under **Administration > Logs** for app-related errors during startup.

### IPv6-Only Domains Not Resolving

**Symptoms:** Domains with only IPv6 addresses return no results

**Root Cause:** This is expected behavior. The app only filters AAAA records when A records are available.

**Diagnostic Steps:**

1. Verify the domain has no A records: `dig A example.com`
2. Confirm AAAA records exist: `dig AAAA example.com`
3. Check if domain should be in `bypassDomains`

**Resolution:**

For domains that should remain IPv6-only, add them to `bypassDomains`:

```json
"bypassDomains": [
  "ipv6-only-site.com"
]
```

This is the intended design: the app preserves IPv6 connectivity for IPv6-only infrastructure.

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
