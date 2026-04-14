# DNS Rebinding Protection App

## Summary

A DNS App for Technitium DNS Server that protects against DNS rebinding attacks by filtering private IP addresses from DNS responses for non-local domain names.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsPostProcessor`
- Runs as: a post-processor (operates on DNS responses after core resolution).

## Overview

This application extends Technitium DNS Server by implementing **IDnsPostProcessor** to analyze DNS query responses before they are returned to clients. The app prevents DNS rebinding attacks by:

- **Filtering private IP addresses** from A and AAAA records for public domain names
- **Allowing private IP addresses** only for explicitly configured private domains
- **Supporting IPv4 and IPv6** private network ranges per RFC 1918 and RFC 4193
- **Bypassing protection** for trusted client networks when needed
- **Preserving authoritative responses** to avoid interfering with locally hosted zones

This protection is critical for environments where clients access both internal and external resources, preventing malicious websites from accessing internal network services.

## ⚠️ Important Warning: Impact on Legitimate Private IP Responses

This app will **remove private IP addresses** from DNS responses for any domain name not explicitly listed in the `privateDomains` configuration.

**Processing behavior:**

- If a public DNS query returns private IP addresses (e.g., `example.com` → `192.168.1.1`), those records **will be removed** from the response
- Only domains listed in `privateDomains` are permitted to resolve to private IP addresses
- Authoritative responses from local zones are **never filtered**, as rebinding is considered intentional in this context

**Configuration options:**

- **Option A**: Add all legitimate internal domain names to the `privateDomains` array
- **Option B**: Disable the app entirely if private IP responses are required for domains you cannot enumerate
- **Option C**: Add trusted client networks to `bypassNetworks` to exclude them from protection

**Processing order:**

The app processes responses **after** the DNS server completes resolution but **before** sending the response to the client. Filtering applies only to non-authoritative answers.

## Installation

1. Open the Technitium DNS Server web console

2. Navigate to **Apps** in the left menu

3. Click **Install App** or **Update App** if already installed

4. Upload the compiled `DnsRebindingProtectionApp.dll` and `dnsApp.config` files

5. Configure the app by editing `dnsApp.config` as described below

## Configuration

The application is configured through the `dnsApp.config` file located in the app's installation directory.

The configuration uses a JSON structure with four root-level properties that control protection behavior, network definitions, and domain exemptions.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableProtection` | Boolean | `true` | Master switch to enable or disable DNS rebinding protection globally |
| `bypassNetworks` | Array of Strings | `[]` | List of CIDR network ranges for client IP addresses that should bypass protection entirely |
| `privateNetworks` | Array of Strings | See below | List of CIDR network ranges considered private; responses containing these IPs will be filtered |
| `privateDomains` | Array of Strings | `["home.arpa"]` | List of domain names permitted to resolve to private IP addresses without filtering |

### Private Networks Configuration

The `privateNetworks` array defines which IP address ranges are considered private and subject to rebinding protection.

**Default configuration includes all RFC-defined private ranges:**

```json
"privateNetworks": [
  "10.0.0.0/8",
  "127.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "fc00::/7",
  "fe80::/10"
]
```

**Purpose**: Any DNS response containing IP addresses within these ranges will be filtered unless the domain is listed in `privateDomains` or the client is in `bypassNetworks`.

**Use case**: Organizations may customize this list to include additional private address space (e.g., Carrier-Grade NAT `100.64.0.0/10`) or remove ranges not used in their environment.

### Private Domains Configuration

The `privateDomains` array specifies domain names that are **exempt from filtering** and may legitimately resolve to private IP addresses.

**Format conventions:**

- Domain names are case-insensitive
- Parent zone matching is supported (e.g., `internal.local` also permits `server.internal.local`)
- Do not include wildcards; subdomain matching is automatic

**Example:**

```json
"privateDomains": [
  "home.arpa",
  "internal.local",
  "corp.example.com"
]
```

### Bypass Networks Configuration

The `bypassNetworks` array defines client IP ranges that **completely bypass rebinding protection**.

**Purpose**: Trusted networks (e.g., administrative subnets) can receive unfiltered DNS responses.

**Use case**: Internal management networks or developer workstations requiring access to split-horizon DNS configurations.

**Example:**

```json
"bypassNetworks": [
  "10.50.0.0/24",
  "192.168.100.0/24"
]
```

## Example Configuration

```json
{
  "enableProtection": true,
  "bypassNetworks": [
    "10.50.0.0/24"
  ],
  "privateNetworks": [
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10"
  ],
  "privateDomains": [
    "home.arpa",
    "internal.local",
    "corp.example.com",
    "lab.local"
  ]
}
```

This configuration:

- Enables protection globally
- Exempts clients in `10.50.0.0/24` from all filtering
- Filters all standard RFC 1918/4193 private IP addresses
- Permits private IPs for `*.home.arpa`, `*.internal.local`, `*.corp.example.com`, and `*.lab.local`

## Supported Network Address Formats

The app supports standard CIDR notation for both IPv4 and IPv6 networks:

**IPv4 CIDR notation:**

```
192.168.1.0/24
10.0.0.0/8
```

**IPv6 CIDR notation:**

```
fc00::/7
fe80::/10
2001:db8::/32
```

**Single host addresses:**

```
192.168.1.1/32
::1/128
```

## How Rebinding Protection Works

The app applies the following processing pipeline to each DNS response:

1. **Bypass check**: If `enableProtection` is `false` or the response has the `AuthoritativeAnswer` flag set, return the response unmodified

2. **Client network check**: Compare the client IP address against each entry in `bypassNetworks`; if matched, return the response unmodified

3. **Record inspection**: For each A or AAAA record in the answer section:
   - Extract the domain name and IP address
   - Check if the domain matches any entry in `privateDomains` (including parent zones)
   - If the domain is private, skip to the next record
   - If the domain is public, check if the IP address falls within any `privateNetworks` range
   - If the IP is private, mark the record for removal

4. **Response modification**: If any records were marked for removal, create a new response with only the allowed records

5. **Client delivery**: Return either the original response (if no rebinding detected) or the filtered response

## Use Cases

**Enterprise split-horizon DNS deployment**: Allow internal domain names like `intranet.corp.local` to resolve to `10.x.x.x` addresses while blocking external domains from returning private IPs.

**ISP customer protection**: Prevent DNS rebinding attacks against residential gateway devices (typically at `192.168.x.x`) by filtering private IP responses for all public domain queries.

**Home network security**: Protect IoT devices and home servers from cross-site request forgery attacks leveraging DNS rebinding against `192.168.1.x` addresses.

**Development environment isolation**: Use `bypassNetworks` to allow developer machines unrestricted DNS access while protecting production client networks.

**Multi-site organization**: Configure different `privateDomains` lists for each site's internal naming conventions (e.g., `site1.internal`, `site2.internal`).

**IPv6 dual-stack protection**: Prevent rebinding attacks targeting unique local addresses (`fc00::/7`) and link-local addresses (`fe80::/10`) in IPv6-enabled networks.

## Troubleshooting

### Internal domain names not resolving

**Symptoms**: Queries for internal domain names return empty responses or SERVFAIL.

**Diagnostic steps**:

1. Check the DNS server logs for rebinding protection activity
2. Verify the domain name is listed in `privateDomains` configuration
3. Confirm parent zone matching is correct (e.g., `example.local` permits `host.example.local`)

**Resolution**: Add the affected domain to the `privateDomains` array in `dnsApp.config`.

### Protection not activating for public domains

**Symptoms**: Public domain names are resolving to private IP addresses without filtering.

**Diagnostic steps**:

1. Verify `enableProtection` is set to `true`
2. Check if the client IP is listed in `bypassNetworks`
3. Confirm the DNS response does not have the `AuthoritativeAnswer` flag set
4. Verify the IP address is included in `privateNetworks`

**Resolution**: Review the configuration for unintended bypass rules or missing private network definitions.

### Legitimate private IP responses being filtered

**Symptoms**: Split-horizon DNS or internal services are inaccessible due to filtered responses.

**Diagnostic steps**:

1. Identify the affected domain names
2. Check if the domains are listed in `privateDomains`
3. Verify parent zone matching is functioning

**Resolution**: Add the affected domains to `privateDomains` or add the client network to `bypassNetworks`.

### Configuration changes not taking effect

**Symptoms**: Modifications to `dnsApp.config` do not change app behavior.

**Diagnostic steps**:

1. Verify the `dnsApp.config` file is in the correct app directory
2. Check JSON syntax validity using a JSON validator
3. Review DNS server logs for configuration parsing errors

**Resolution**: Restart the Technitium DNS Server application or reload the app through the web console.
