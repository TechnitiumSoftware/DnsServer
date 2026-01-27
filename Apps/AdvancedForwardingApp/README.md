# Advanced Forwarding App

A DNS App for Technitium DNS Server that provides advanced DNS forwarding capabilities with support for DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS-over-QUIC (DoQ), and conditional forwarding based on domain names, network groups, and QNAME patterns. This app extends the core DNS server's forwarding functionality by enabling fine-grained control over upstream resolver selection, protocol selection, and query routing based on flexible matching rules.

## Overview

The **Advanced Forwarding App** extends Technitium DNS Server's native forwarding capabilities by introducing:

- **Protocol-specific forwarding**: Route queries via UDP, TCP, TLS, HTTPS, or QUIC to upstream resolvers
- **Conditional domain-based forwarding**: Forward specific domains or domain patterns to designated upstream servers
- **Network group-based routing**: Apply different forwarding policies based on client IP address or subnet
- **Wildcard and pattern matching**: Use `*` wildcards for flexible domain matching
- **Forwarder health management**: Automatic failover and retry logic with configurable concurrency
- **Response customization**: Control DNSSEC, EDN Client Subnet (ECS), and caching behavior per forwarder

This app is designed for **network administrators** and **DNS operators** who require granular control over DNS query routing beyond simple recursive resolution or basic forwarding.

## ⚠️ Important Warning: Overlap with Core DNS Forwarders

This app provides forwarding functionality that may overlap with Technitium DNS Server's built-in **Forwarders** feature.

**You should choose ONE approach:**

- **Option A**: Use the core DNS Server **Forwarders** feature for simple, global forwarding to a set of upstream servers
- **Option B**: Use this **Advanced Forwarding App** for conditional, protocol-specific, or network-based forwarding rules

**Do NOT enable both simultaneously** unless you fully understand the processing order and interaction:

1. DNS Apps execute **before** core forwarders in the query pipeline
2. If this app returns a forwarded response, core forwarders will **not** be invoked
3. If this app does not match a rule or returns no result, the query continues to core forwarding or recursion

Using both mechanisms without clear separation may result in unexpected behavior, duplicate queries, or routing conflicts.

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** in the main menu
3. Click **Install App** or **Update App** if already installed
4. Locate **AdvancedForwardingApp** in the list and confirm installation
5. Configure the app via the **Apps** configuration interface or by editing `dnsApp.config`

## Configuration

The app is configured via a JSON file named **`dnsApp.config`**, located in the app's installation directory.

The configuration supports **root-level options**, **forwarder definitions**, and **network group-based forwarding rules**.

All configuration must be valid JSON. Invalid syntax will prevent the app from loading.

### Root Configuration Options

| Property | Type | Default | Description |
| ---------- | ------ | --------- | ------------- |
| `enableForwarding` | Boolean | `true` | Master switch to enable or disable all forwarding rules globally |
| `forwarders` | Array | `[]` | List of forwarder definitions (upstream DNS servers) available for use in forwarding groups |
| `forwarderGroups` | Array | `[]` | List of forwarding rule groups, each targeting specific domains or networks |

### Forwarder Configuration

Each entry in the `forwarders` array defines an upstream DNS server with protocol and behavior settings.

**Structure:**

```json
{
  "name": "Cloudflare-DoH",
  "forwarder": "https://cloudflare-dns.com/dns-query",
  "dnssecValidation": true,
  "proxyType": "None",
  "proxyAddress": null,
  "proxyPort": 0,
  "proxyUsername": null,
  "proxyPassword": null
}
```

**Forwarder Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | Required | Unique identifier for the forwarder, referenced in forwarding groups |
| `forwarder` | String | Required | Upstream DNS server address. Supports `ip:port`, `tcp://ip:port`, `tls://hostname:port`, `https://url`, `quic://hostname:port` |
| `dnssecValidation` | Boolean | `false` | Enable DNSSEC validation for responses from this forwarder |
| `proxyType` | String | `"None"` | Proxy type: `None`, `Http`, `Socks5` |
| `proxyAddress` | String | `null` | Proxy server address (if `proxyType` is not `None`) |
| `proxyPort` | Integer | `0` | Proxy server port |
| `proxyUsername` | String | `null` | Proxy authentication username |
| `proxyPassword` | String | `null` | Proxy authentication password |

**Supported Forwarder Protocol Formats:**

- **UDP/TCP (default)**: `8.8.8.8` or `8.8.8.8:53`
- **TCP only**: `tcp://8.8.8.8:53`
- **DNS-over-TLS (DoT)**: `tls://dns.google:853`
- **DNS-over-HTTPS (DoH)**: `https://dns.google/dns-query`
- **DNS-over-QUIC (DoQ)**: `quic://dns.adguard.com:853`

### Forwarder Group Configuration

Each entry in the `forwarderGroups` array defines a forwarding rule with domain matching and network targeting.

**Structure:**

```json
{
  "name": "Corporate-Internal",
  "enabled": true,
  "forwarderNames": ["Internal-DNS-1", "Internal-DNS-2"],
  "domains": ["*.internal.corp", "*.local"],
  "networks": ["10.0.0.0/8", "172.16.0.0/12"]
}
```

**Forwarder Group Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | Required | Descriptive name for the forwarding group |
| `enabled` | Boolean | `true` | Enable or disable this forwarding group |
| `forwarderNames` | Array | Required | List of forwarder names (from `forwarders` array) to use for this group |
| `domains` | Array | `[]` | List of domain patterns to match. Supports exact match and `*` wildcard |
| `networks` | Array | `[]` | List of client IP addresses or CIDR subnets. If empty, applies to all clients |

**Domain Matching Rules:**

- **Exact match**: `example.com` matches only `example.com`
- **Wildcard subdomain**: `*.example.com` matches `sub.example.com`, `deep.sub.example.com`, but **not** `example.com`
- **Wildcard suffix**: `example.*` matches `example.com`, `example.net`, etc.
- **Full wildcard**: `*` matches all domains (use with caution)

**Network Matching Rules:**

- If `networks` is **empty** or **not specified**, the group applies to **all clients**
- If `networks` contains one or more entries, the group applies **only** to clients whose IP matches a listed subnet or address
- Supports both IPv4 and IPv6 CIDR notation

## Example Configuration

```json
{
  "enableForwarding": true,
  "forwarders": [
    {
      "name": "Cloudflare-DoH",
      "forwarder": "https://cloudflare-dns.com/dns-query",
      "dnssecValidation": true,
      "proxyType": "None"
    },
    {
      "name": "Google-DoT",
      "forwarder": "tls://dns.google:853",
      "dnssecValidation": true,
      "proxyType": "None"
    },
    {
      "name": "Quad9-UDP",
      "forwarder": "9.9.9.9:53",
      "dnssecValidation": false,
      "proxyType": "None"
    },
    {
      "name": "Internal-DNS",
      "forwarder": "tcp://10.0.1.10:53",
      "dnssecValidation": false,
      "proxyType": "None"
    }
  ],
  "forwarderGroups": [
    {
      "name": "Internal-Domains",
      "enabled": true,
      "forwarderNames": ["Internal-DNS"],
      "domains": ["*.internal.corp", "*.local"],
      "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    },
    {
      "name": "External-Secure",
      "enabled": true,
      "forwarderNames": ["Cloudflare-DoH", "Google-DoT"],
      "domains": [],
      "networks": []
    },
    {
      "name": "Guest-Network",
      "enabled": true,
      "forwarderNames": ["Quad9-UDP"],
      "domains": [],
      "networks": ["192.168.100.0/24"]
    }
  ]
}
```

## Supported Domain Pattern Formats

The `domains` array in each forwarder group supports the following matching patterns:

### Exact Match

```json
"domains": ["example.com"]
```

Matches: `example.com`  
Does not match: `sub.example.com`, `www.example.com`

### Wildcard Subdomain Match

```json
"domains": ["*.example.com"]
```

Matches: `www.example.com`, `api.example.com`, `deep.sub.example.com`  
Does not match: `example.com` (root domain)

### Wildcard TLD Match

```json
"domains": ["example.*"]
```

Matches: `example.com`, `example.net`, `example.org`  
Does not match: `sub.example.com`

### Global Wildcard (Use with Caution)

```json
"domains": ["*"]
```

Matches: **All domains**

**Warning**: Use only as a fallback or default rule, and ensure it is the last group evaluated.

## How Advanced Forwarding Works

The app processes DNS queries using the following pipeline:

1. **Global Enable Check**: If `enableForwarding` is `false`, the app immediately passes the query to the next handler
2. **Group Iteration**: The app evaluates each forwarder group in the order defined in `forwarderGroups`
3. **Network Match**: If the group specifies `networks`, the client IP is checked against the list. If no match, the group is skipped
4. **Domain Match**: The query's QNAME is compared against the `domains` list using wildcard and exact match logic. If no match, the group is skipped
5. **Forwarder Selection**: If both network and domain conditions are met, the app selects the forwarders listed in `forwarderNames`
6. **Query Forwarding**: The query is forwarded to the selected upstream resolver(s) using the specified protocol (UDP, TCP, DoT, DoH, DoQ)
7. **Response Return**: The first successful response is returned to the client. If all forwarders fail, the query continues to the next DNS handler or fails

**Processing stops at the first matching group.** Subsequent groups are not evaluated.

## Use Cases

1. **Corporate Split-Horizon DNS:** Forward internal domain queries (e.g., `*.corp`, `*.local`) to internal DNS servers, while external queries are forwarded to public encrypted DNS resolvers.
2. **Geographic or Network-Based Routing:** Route queries from guest networks to filtered or rate-limited upstream resolvers, while trusted internal networks use high-performance or DNSSEC-validating forwarders.
3. **Protocol Enforcement:** Enforce DNS-over-HTTPS or DNS-over-TLS for all external queries to prevent eavesdropping or tampering, while using plain DNS for trusted internal zones.
4. **ISP or Hosting Provider Multi-Tenancy:** Apply different forwarding policies per customer or subnet, enabling per-tenant DNS filtering, logging, or upstream provider selection.
5. **Failover and Redundancy:** Configure multiple forwarders per group to ensure high availability. The app will attempt each forwarder in sequence until a valid response is received.
6. **DNSSEC Validation Enforcement:** Enable `dnssecValidation` on specific forwarders to ensure cryptographic validation of responses, protecting against cache poisoning or spoofing attacks.

## Troubleshooting

### Forwarder Not Being Used

**Symptoms**: Queries are not forwarded to the expected upstream server.

**Diagnostic Steps**:

1. Check that `enableForwarding` is `true` in `dnsApp.config`
2. Verify the forwarder group is `enabled`
3. Confirm the client IP matches the `networks` filter (if specified)
4. Confirm the query domain matches one of the `domains` patterns
5. Check logs for syntax errors or configuration reload failures

**Resolution**: Ensure the forwarder group is correctly defined and that the client and query meet all match criteria. Review the order of forwarder groups—matching stops at the first match.

### Domain Wildcard Not Matching

**Symptoms**: Wildcard domain patterns do not match expected queries.

**Diagnostic Steps**:

1. Verify wildcard syntax: `*.example.com` matches subdomains, **not** the root `example.com`
2. Check for trailing dots in domain names (e.g., `example.com.` vs `example.com`)
3. Review logs for QNAME as seen by the app

**Resolution**: Adjust domain patterns to include both root and wildcard entries if needed:

```json
"domains": ["example.com", "*.example.com"]
```

### DNS-over-HTTPS or DNS-over-TLS Connection Failures

**Symptoms**: Queries time out or fail when using DoH or DoT forwarders.

**Diagnostic Steps**:

1. Verify the upstream resolver URL or hostname is correct
2. Check firewall rules allow outbound connections on port 853 (DoT) or 443 (DoH)
3. Test connectivity using `curl` or `openssl s_client`:

    ```bash
    openssl s_client -connect dns.google:853
    ```

4. Review proxy settings if `proxyType` is configured

**Resolution**: Ensure network connectivity and correct upstream endpoint configuration. Verify TLS certificates are valid and trusted.

### DNSSEC Validation Failures

**Symptoms**: DNSSEC-enabled forwarders return SERVFAIL or no response.

**Diagnostic Steps**:

1. Verify the upstream forwarder supports DNSSEC
2. Check that the queried domain has valid DNSSEC signatures
3. Test the domain with an external DNSSEC validator (e.g., `dnsviz.net`)
4. Review logs for DNSSEC-related errors

**Resolution**: Disable `dnssecValidation` for the forwarder, or fix DNSSEC issues at the authoritative zone level.

### Configuration Not Reloading

**Symptoms**: Changes to `dnsApp.config` are not applied.

**Diagnostic Steps**:

1. Verify JSON syntax using a validator (e.g., `jsonlint.com`)
2. Check DNS server logs for parsing errors
3. Restart the DNS app or reload the configuration from the web console

**Resolution**: Correct JSON syntax errors and reload the app configuration. Ensure the file is saved with UTF-8 encoding.

### Multiple Forwarder Groups Overlapping

**Symptoms**: Unexpected forwarder is used for a query.

**Diagnostic Steps**:

1. Remember that forwarder groups are evaluated **in order**
2. The **first matching group** is used; subsequent groups are ignored
3. Review the order of groups in `forwarderGroups`

**Resolution**: Reorder forwarder groups so more specific rules appear before general rules. Place wildcard or default groups at the end.

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
