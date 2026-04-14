# DNS64 App

A DNS App for Technitium DNS Server that implements RFC 6147 DNS64 functionality to enable IPv6-only clients to access IPv4-only resources through DNS protocol translation.

This app extends the Technitium DNS Server to synthesize AAAA records from A records, allowing IPv6-only clients to discover and access IPv4 resources when used in conjunction with a NAT64 gateway. The app operates as both a post-processor for recursive queries and an authoritative request handler for reverse DNS lookups within the DNS64 address space.

## Overview

DNS64 App implements **DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers** as defined in RFC 6147. The app enables seamless connectivity for IPv6-only networks by translating IPv4 addresses into synthesized IPv6 addresses using configurable prefix mappings.

Key capabilities include:

- **Automatic AAAA record synthesis** from A records for AAAA queries
- **Network-based group policies** for fine-grained DNS64 control
- **Configurable IPv6 prefix mappings** with support for standard prefix lengths (32, 40, 48, 56, 64, 96)
- **IPv6 address exclusions** to prevent synthesis for specific ranges
- **Reverse DNS (PTR) handling** for synthesized IPv6 addresses
- **DNSSEC-aware operation** that bypasses DNS64 when DNSSEC validation is requested

This app provides critical infrastructure support for dual-stack migration strategies and IPv6-only network deployments.

## ⚠️ Important Warning: NAT64 Dependency

DNS64 **must** be deployed in conjunction with a functional NAT64 gateway. The app performs DNS protocol translation only—it does not provide network address translation.

**Operational Risk:**

Installing and enabling DNS64 App without a corresponding NAT64 gateway in place will cause **connectivity failures** for IPv6-only clients attempting to reach IPv4-only destinations. Synthesized AAAA records will resolve to IPv6 addresses that cannot be routed without NAT64.

**Deployment Options:**

- **Option A:** Deploy NAT64 gateway first, then enable DNS64 App
- **Option B:** Configure DNS64 App with `enableDns64: false` initially, deploy NAT64, then enable DNS64

**Processing Order:**

DNS64 operates as a post-processor in the DNS resolution pipeline. It processes responses **after** recursive resolution and **before** returning results to clients.

## Installation

1. Open the Technitium DNS Server web console

2. Navigate to **Apps** in the main menu

3. Click **Install/Update** and upload the DNS64 App package, or install directly from the App Store

4. Configure the app by editing the `dnsApp.config` file or using the web interface

## Configuration

The DNS64 App is configured through the `dnsApp.config` JSON file. The configuration defines global settings, network-to-group mappings, and per-group DNS64 policies.

All configuration options are documented below. The structure supports hierarchical policy enforcement based on client network origin.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | integer | 30 | Processing priority when multiple apps implement `IDnsApplicationPreference`. Lower values execute first. |
| `enableDns64` | boolean | (required) | Global DNS64 enable flag. When `false`, app is inactive regardless of group settings. |
| `networkGroupMap` | object | (required) | Maps client network addresses (CIDR notation) to named groups. Longest prefix match determines group assignment. |
| `groups` | array | (required) | Array of group objects defining DNS64 policies. Groups are referenced by name from `networkGroupMap`. |

### Network Group Mapping

The `networkGroupMap` object maps client source networks to named policy groups using CIDR notation as keys and group names as values.

**Purpose:**

Enables differentiated DNS64 behavior based on client network origin. Supports granular policy enforcement for internal vs. external clients, different VLANs, or trust zones.

**Matching Logic:**

The app performs longest prefix match. If a client IP matches multiple networks, the most specific (longest prefix length) mapping is selected.

**JSON Example:**

```json
"networkGroupMap": {
  "::/0": "default-group",
  "2001:db8:1000::/48": "internal-group",
  "2001:db8:2000::/48": "guest-group"
}
```

### Group Configuration

Each group object defines a complete DNS64 policy.

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | (required) | Unique identifier for the group. Referenced by `networkGroupMap`. |
| `enableDns64` | boolean | (required) | Group-level DNS64 enable flag. Allows per-group activation/deactivation. |
| `dns64PrefixMap` | object | (required) | Maps IPv4 network ranges to DNS64 IPv6 prefixes. Keys are IPv4 CIDR, values are IPv6 prefix strings or `null`. |
| `excludedIpv6` | array | `[]` | Array of IPv6 network addresses (CIDR) to exclude from DNS64 processing. Existing AAAA records in these ranges suppress synthesis. |

### DNS64 Prefix Mapping

The `dns64PrefixMap` object within each group defines how IPv4 addresses are translated into IPv6 addresses.

**Structure:**

Keys are IPv4 network addresses in CIDR notation. Values are either:

- **IPv6 prefix string** (CIDR notation) to use for synthesis
- **`null`** to exclude the IPv4 range from DNS64 processing

**Prefix Length Constraints:**

DNS64 prefixes must use one of the following RFC 6147-compliant prefix lengths: **32, 40, 48, 56, 64, or 96**.

**Matching Logic:**

Longest prefix match. The most specific IPv4 network match determines the DNS64 prefix used for synthesis.

**JSON Example:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "64:ff9b::/96",
  "10.0.0.0/8": null,
  "172.16.0.0/12": null,
  "192.168.0.0/16": null,
  "203.0.113.0/24": "2001:db8:64::/96"
}
```

**Explanation:**

- All IPv4 addresses use `64:ff9b::/96` prefix (well-known prefix from RFC 6052)
- RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are excluded
- Public range 203.0.113.0/24 uses custom prefix `2001:db8:64::/96`

### IPv6 Exclusion List

The `excludedIpv6` array prevents DNS64 synthesis when existing AAAA records fall within specified IPv6 ranges.

**Purpose:**

Prevents synthesis when legitimate IPv6 addresses already exist but should not be used (e.g., IPv4-mapped IPv6 addresses).

**Common Exclusions:**

- `::ffff:0:0/96` — IPv4-mapped IPv6 addresses (RFC 4291 Section 2.5.5.2)

**JSON Example:**

```json
"excludedIpv6": [
  "::ffff:0:0/96",
  "2001:db8:exclude::/48"
]
```

## Example Configuration

```json
{
  "appPreference": 30,
  "enableDns64": true,
  "networkGroupMap": {
    "::/0": "everyone",
    "2001:db8:internal::/48": "internal-ipv6"
  },
  "groups": [
    {
      "name": "everyone",
      "enableDns64": true,
      "dns64PrefixMap": {
        "0.0.0.0/0": "64:ff9b::/96",
        "10.0.0.0/8": null,
        "172.16.0.0/12": null,
        "192.168.0.0/16": null
      },
      "excludedIpv6": [
        "::ffff:0:0/96"
      ]
    },
    {
      "name": "internal-ipv6",
      "enableDns64": true,
      "dns64PrefixMap": {
        "0.0.0.0/0": "2001:db8:64::/96",
        "10.0.0.0/8": "2001:db8:64:a::/96",
        "172.16.0.0/12": "2001:db8:64:ac::/96",
        "192.168.0.0/16": "2001:db8:64:c0::/96"
      },
      "excludedIpv6": [
        "::ffff:0:0/96"
      ]
    }
  ]
}
```

## DNS64 Prefix Formats

The app supports standard RFC 6147 prefix lengths. The IPv4 address is embedded within the IPv6 prefix according to the prefix length.

**Supported Prefix Lengths:**

| Prefix Length | Format | IPv4 Embedding |
| --- | --- | --- |
| `/32` | `pppp:pppp::/32` | Bits 32-63 and 64-95 |
| `/40` | `pppp:pppp:pp00::/40` | Bits 40-63 and 64-95 |
| `/48` | `pppp:pppp:pppp::/48` | Bits 48-63 and 64-95 |
| `/56` | `pppp:pppp:pppp:pp00::/56` | Bits 56-63 and 64-95 |
| `/64` | `pppp:pppp:pppp:pppp::/64` | Bits 64-95 |
| `/96` | `pppp:pppp:pppp:pppp:pppp:pppp::/96` | Bits 96-127 |

**Well-Known Prefix:**

RFC 6052 defines `64:ff9b::/96` as the well-known prefix for DNS64/NAT64 deployments.

**Example:**

IPv4 address `192.0.2.1` with prefix `64:ff9b::/96` becomes `64:ff9b::192.0.2.1` or `64:ff9b::c000:201`.

## How DNS64 Processing Works

The DNS64 App implements two distinct processing paths:

### AAAA Query Processing (Post-Processor)

1. **Request Validation:** App checks if DNS64 is enabled globally and DNSSEC is not requested
2. **Response Analysis:** App evaluates recursive resolver response for AAAA query
3. **Group Selection:** Client source IP is matched against `networkGroupMap` using longest prefix match
4. **Exclusion Check:** If AAAA records exist and fall outside `excludedIpv6` ranges, no synthesis occurs
5. **A Record Query:** If no valid AAAA records exist, app performs internal A record query
6. **Prefix Mapping:** Each A record is matched against `dns64PrefixMap` using longest prefix match
7. **AAAA Synthesis:** IPv4 addresses are embedded in IPv6 prefix to generate synthesized AAAA records
8. **Response Construction:** Synthesized AAAA records are added to response with TTL capped by SOA minimum

### PTR Query Processing (Authoritative Handler)

1. **Request Validation:** App checks if query is PTR for `.ip6.arpa` domain
2. **Group Selection:** Client source IP is matched against `networkGroupMap`
3. **Prefix Match:** Reverse IPv6 address is matched against configured `dns64PrefixMap` values
4. **IPv4 Extraction:** IPv4 address is extracted from synthesized IPv6 address
5. **CNAME Response:** App returns authoritative CNAME record pointing to `.in-addr.arpa` domain
6. **Recursive Resolution:** DNS server follows CNAME to resolve PTR from IPv4 reverse zone

## Use Cases

1. **IPv6-Only Client Networks:** Deploy DNS64 App to enable IPv6-only clients to access IPv4-only internet resources without dual-stack client configuration. Commonly used in mobile carrier networks and modern enterprise IPv6 migrations.
2. **Dual-Stack Transition Strategy:** Use DNS64 to provide fallback connectivity for IPv6-capable clients when communicating with legacy IPv4-only services during incremental IPv6 deployment.
3. **ISP IPv6 Service Delivery:** Internet service providers deploy DNS64 alongside carrier-grade NAT64 to offer IPv6-only residential or business services while maintaining backward compatibility with IPv4 internet.
4. **Enterprise Internal IPv6 Migration:** Organizations deploying IPv6-only internal networks use DNS64 to maintain access to IPv4-only internal applications and third-party SaaS platforms during migration.
5. **Testing and Development Environments:** Network engineers use DNS64 in lab environments to simulate IPv6-only client conditions and validate application IPv6 readiness without full infrastructure changes.
6. **Geographic DNS64 Prefix Routing:** Organizations with multiple regional NAT64 gateways use network group mappings to direct clients to geographically appropriate DNS64 prefixes and NAT64 infrastructure.

## Troubleshooting

### DNS64 Not Synthesizing AAAA Records

**Symptoms:** IPv6-only clients receive no AAAA records for domains that should trigger DNS64 synthesis.

**Diagnostic Steps:**

1. Verify `enableDns64: true` at both root and group level
2. Confirm client source IP matches a network in `networkGroupMap`
3. Check that target IPv4 address is not excluded via `dns64PrefixMap: null` mapping
4. Verify DNSSEC is not requested by client (app bypasses DNSSEC queries)
5. Confirm existing AAAA records are not present or are in `excludedIpv6` ranges

**Configuration Check:**

Review `dns64PrefixMap` for correct CIDR notation and prefix lengths (32, 40, 48, 56, 64, 96 only).

**Logs:**

Enable DNS server query logging to observe DNS64 post-processing behavior and internal A record queries.

### Synthesized AAAA Records Not Reachable

**Symptoms:** Clients receive AAAA records but connections fail or time out.

**Diagnostic Steps:**

1. **Verify NAT64 gateway is operational and reachable from client network**
2. Confirm NAT64 prefix configuration matches DNS64 `dns64PrefixMap` prefixes
3. Test NAT64 connectivity using ping6 to known IPv4 address: `ping6 64:ff9b::8.8.8.8`
4. Check routing for DNS64 prefix range to NAT64 gateway
5. Verify NAT64 gateway has IPv4 routing to destination

**Common Cause:**

DNS64 deployed without corresponding NAT64 infrastructure.

### Private IPv4 Addresses Being Synthesized

**Symptoms:** RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are converted to IPv6.

**Resolution:**

Add exclusions to `dns64PrefixMap`:

```json
"dns64PrefixMap": {
  "10.0.0.0/8": null,
  "172.16.0.0/12": null,
  "192.168.0.0/16": null
}
```

Private IPv4 addresses should generally not be translated unless dual-stack NAT64 is explicitly configured.

### Reverse DNS (PTR) Queries Failing

**Symptoms:** PTR queries for synthesized IPv6 addresses return NXDOMAIN.

**Diagnostic Steps:**

1. Verify synthesized IPv6 address falls within configured DNS64 prefix
2. Confirm corresponding IPv4 reverse zone (`.in-addr.arpa`) exists and is resolvable
3. Check DNS server logs for CNAME processing from `.ip6.arpa` to `.in-addr.arpa`

**Expected Behavior:**

App returns authoritative CNAME from `.ip6.arpa` to `.in-addr.arpa`, then server recursively resolves PTR.

### DNS64 Prefix Length Error

**Symptoms:** Configuration validation fails with "DNS64 prefix can have only the following prefixes" error.

**Resolution:**

Verify all DNS64 prefix values in `dns64PrefixMap` use only permitted prefix lengths: `/32`, `/40`, `/48`, `/56`, `/64`, or `/96`.

**Invalid Example:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "2001:db8::/80"  // Invalid - /80 is not one of the supported prefix lengths
}
```

**Corrected Example:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "2001:db8:64::/96"
}
```
