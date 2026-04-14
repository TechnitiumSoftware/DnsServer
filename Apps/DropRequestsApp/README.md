# Drop Requests App

A DNS App for Technitium DNS Server that drops incoming DNS requests based on network source addresses and DNS question patterns.

This application extends the core DNS Server by intercepting requests at the entry point and applying configurable filtering rules before queries reach the resolution pipeline. It provides administrators with granular control over which DNS queries are processed, enabling network segmentation, abuse mitigation, and security enforcement.

## Overview

The Drop Requests App provides **pre-resolution request filtering** for Technitium DNS Server, enabling administrators to:

- **Block requests from specific networks** using CIDR notation
- **Allow requests only from trusted networks** (allowlist mode)
- **Drop malformed or invalid DNS packets** to reduce parser load
- **Filter DNS questions by name and record type** to prevent abuse
- **Implement zone-level blocking** to drop all queries for a domain and its subdomains

This application is designed for **system administrators, ISPs, and security-conscious organizations** requiring traffic shaping, DDoS mitigation, or network policy enforcement at the DNS layer.

## Installation

1. Open the Technitium DNS Server **web console**

2. Navigate to **Apps** in the main menu

3. Click **Install/Update** and select the Drop Requests App

4. Configure the `dnsApp.config` file according to your network policy requirements

## Configuration

The Drop Requests App is configured using the `dnsApp.config` file located in the application's installation directory. This file uses JSON format and supports network-based filtering, question-based filtering, and malformed packet detection.

All configuration options are documented below.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableBlocking` | boolean | `true` | Master switch to enable or disable all blocking functionality. When set to `false`, all requests are allowed regardless of other rules. |
| `dropMalformedRequests` | boolean | `false` | Silently drops DNS requests that fail to parse correctly. Useful for mitigating parser-based attacks or reducing log noise from malformed packets. |
| `allowedNetworks` | array of strings | `[]` | List of network addresses (IP or CIDR) from which requests are always allowed. If specified, requests from networks not in this list are evaluated against blocked networks and questions. Empty array disables allowlist mode. |
| `blockedNetworks` | array of strings | `[]` | List of network addresses (IP or CIDR) from which requests are always dropped. Processed after `allowedNetworks`. |
| `blockedQuestions` | array of objects | `[]` | List of DNS question patterns to block. Each object defines name, type, and zone-blocking behavior. See [Blocked Questions Configuration](#blocked-questions-configuration). |

### Blocked Questions Configuration

Each entry in the `blockedQuestions` array is an object with the following properties:

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | No | The fully qualified domain name (FQDN) to match. Trailing dot is automatically trimmed. If omitted, matches any domain. |
| `blockZone` | boolean | No | When `true`, blocks the specified `name` and all subdomains. When `false`, only exact matches are blocked. Default: `false`. Requires `name` to be specified. |
| `type` | string | No | The DNS record type to block (e.g., `A`, `AAAA`, `ANY`, `RRSIG`). Case-insensitive. If omitted, matches any record type. Must be a valid DNS RR type. |

**Matching Behavior:**

- If only `name` is specified: blocks queries for that exact domain, any record type
- If only `type` is specified: blocks queries for that record type, any domain
- If both `name` and `type` are specified: blocks queries matching both conditions
- If `blockZone` is `true`: blocks the domain and all subdomains matching the type filter

**Example Blocked Question (Zone-Level Blocking):**

```json
{
  "name": "malicious.com",
  "blockZone": true
}
```

This blocks `malicious.com`, `www.malicious.com`, `api.subdomain.malicious.com`, and all other subdomains, for all record types.

**Example Blocked Question (Type-Only Blocking):**

```json
{
  "type": "ANY"
}
```

This blocks all `ANY` queries regardless of domain name.

**Example Blocked Question (Exact Domain and Type):**

```json
{
  "name": "pizzaseo.com",
  "type": "RRSIG"
}
```

This blocks only `RRSIG` queries for `pizzaseo.com` (exact match).

## Network Address Formats

Network addresses in `allowedNetworks` and `blockedNetworks` support the following formats:

- **Single IPv4 Address:** `192.168.1.100`
- **Single IPv6 Address:** `2001:db8::1` or `::1`
- **IPv4 CIDR Notation:** `10.0.0.0/8`, `192.168.0.0/16`
- **IPv6 CIDR Notation:** `fe80::/10`, `2001:db8::/32`

**Example Network List:**

```json
"allowedNetworks": [
  "127.0.0.1",
  "::1",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "2001:db8::/32"
]
```

## Example Configuration

```json
{
  "enableBlocking": true,
  "dropMalformedRequests": false,
  "allowedNetworks": [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "blockedNetworks": [
    "203.0.113.0/24",
    "198.51.100.0/24"
  ],
  "blockedQuestions": [
    {
      "name": "example.com",
      "blockZone": true
    },
    {
      "type": "ANY"
    },
    {
      "name": "pizzaseo.com",
      "type": "RRSIG"
    },
    {
      "name": "sl",
      "type": "ANY"
    },
    {
      "name": "a.a.a.ooooops.space",
      "type": "A"
    }
  ]
}
```

## How Request Filtering Works

The Drop Requests App evaluates each incoming DNS request through the following pipeline:

1. **Blocking Check:** If `enableBlocking` is `false`, allow the request immediately.

2. **Malformed Packet Check:** If `dropMalformedRequests` is `true` and the request contains a parsing exception, drop the request silently.

3. **Allowlist Evaluation:** If `allowedNetworks` is configured, check if the source IP address matches any allowed network. If matched, allow the request. If `allowedNetworks` is empty, skip this step.

4. **Blocklist Evaluation:** Check if the source IP address matches any network in `blockedNetworks`. If matched, drop the request silently.

5. **Question Count Validation:** If the request does not contain exactly one DNS question, drop the request silently.

6. **Question Pattern Matching:** Evaluate the DNS question against all entries in `blockedQuestions`. If any entry matches, drop the request silently.

7. **Allow by Default:** If no blocking rule matched, allow the request to proceed to the DNS resolution pipeline.

**Important:** The allowlist (`allowedNetworks`) takes precedence over the blocklist (`blockedNetworks`). If a network is in both lists, requests from that network are allowed.

## Use Cases

1. **Restrict DNS Server to Private Networks:** Configure `allowedNetworks` with RFC 1918 private address ranges to ensure only internal hosts can query the DNS server, preventing open resolver abuse.
2. **Mitigate DNS Amplification Attacks:** Block `ANY` record queries using a type-based blocked question to reduce amplification attack surface.
3. **Block Known Malicious Domains at Query Time:** Use zone-level blocking to prevent any queries for known malicious domains and their subdomains, reducing the attack surface before resolution occurs.
4. **Enforce Regional or Organizational Network Policies:** Block specific external networks from querying the DNS server using `blockedNetworks`, useful for geofencing or compliance requirements.
5. **Reduce Log Noise from Malformed Packets:** Enable `dropMalformedRequests` to silently discard invalid DNS packets, reducing parser overhead and log volume during DDoS conditions.
6. **Prevent Specific DNSSEC Query Abuse:** Block `RRSIG` or other DNSSEC-related queries for domains known to generate excessive traffic or abuse DNSSEC validation mechanisms.

## Troubleshooting

### Requests Are Not Being Blocked

**Symptom:** DNS queries that should match blocking rules are being resolved normally.

**Diagnostic Steps:**

1. Verify `enableBlocking` is set to `true` in `dnsApp.config`

2. Check the DNS Server **App Logs** for any configuration parsing errors

3. Confirm the source IP address of the request is not in `allowedNetworks` (allowlist overrides all blocks)

4. Verify CIDR notation is correct (e.g., `/24` not `/255.255.255.0`)

5. For question-based blocking, confirm the domain name matches the `name` field exactly (case-insensitive), or that `blockZone` is enabled for subdomain blocking

6. Restart the Technitium DNS Server or reload the app configuration after making changes

### Legitimate Requests Are Being Dropped

**Symptom:** Valid DNS queries from authorized clients are being silently dropped.

**Diagnostic Steps:**

1. Check if the client's IP address is included in `allowedNetworks` when using allowlist mode

2. If `blockedNetworks` is configured, verify the client's IP is not within a blocked CIDR range

3. Review `blockedQuestions` for overly broad patterns (e.g., blocking all `A` records or using `blockZone` on a common TLD)

4. If `dropMalformedRequests` is enabled, verify the client is sending well-formed DNS packets (use `tcpdump` or Wireshark to inspect traffic)

5. Temporarily set `enableBlocking` to `false` to confirm the issue is related to this app

### Malformed Requests Are Not Being Dropped

**Symptom:** Invalid DNS packets are still reaching the resolver or appearing in logs.

**Diagnostic Steps:**

1. Verify `dropMalformedRequests` is set to `true` in `dnsApp.config`

2. Confirm the packets are actually malformed by checking for parsing exceptions in the DNS Server logs

3. Reload the app configuration or restart the DNS Server after enabling the option

4. Some malformed packets may still be logged before being dropped; check the action taken in the logs (`DropSilently`)

### Zone Blocking Is Not Matching Subdomains

**Symptom:** Queries for subdomains are not being blocked when using `blockZone: true`.

**Diagnostic Steps:**

1. Verify the `name` field does not include a trailing dot in the configuration

2. Confirm `blockZone` is set to `true` for the rule

3. Check the DNS question name format in the logs to ensure it matches the expected FQDN structure

4. Test with an exact domain match first (without `blockZone`) to confirm basic name matching is working

**Example Command to Test:**

```bash
dig @<dns-server-ip> subdomain.blocked-domain.com
```

Expected behavior: Request is dropped silently with no response.
