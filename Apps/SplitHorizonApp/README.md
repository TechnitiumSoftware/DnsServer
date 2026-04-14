# Split Horizon App

A DNS App (plugin) for Technitium DNS Server that enables split-horizon DNS functionality and network address translation, allowing administrators to serve different DNS responses and translate IP addresses based on the network location of the requesting client.

This application is designed to:

- **Serve different DNS records** to clients based on their network location (public, private, or custom networks)
- **Translate IP addresses** in DNS responses using configurable 1:1 network mappings
- **Support network-based access control** through DNS resolution policies
- **Enable multi-tenant and geo-distributed architectures** with location-aware DNS responses

It integrates with the Technitium DNS Server runtime to provide **network-aware DNS resolution and address translation** within **primary, secondary, forwarder, and stub zones**.

## Overview

The **Split Horizon App** extends the core DNS server functionality by providing **network-based DNS response differentiation** and **automatic IP address translation**.

Its primary functions include:

- **APP record support** for returning different A, AAAA, or CNAME records based on client network
- **1:1 IP address translation** for forward (A/AAAA) and reverse (PTR) lookups
- **Named network definitions** for reusable network group configurations
- **Network group mapping** with most-specific subnet matching
- **Post-processing pipeline** for modifying responses before client delivery
- **Reverse lookup translation** for internal-to-external IP mapping

This application is intended to support administrators in implementing **policy-driven**, **network-segmented**, and **topology-aware** DNS controls.

## Installation

1. Open the Technitium DNS Server web console.
2. Navigate to **Apps**.
3. Select **Install / Update**.
4. Upload or select the Split Horizon App package.
5. Complete the installation.
6. Configure the app through the Apps interface or by editing `dnsApp.config` directly.
7. Reload the app or restart the DNS service for changes to take effect.

## Configuration

Configuration for Split Horizon App is stored in:

**`dnsApp.config`**

The configuration file defines two independent feature sets:

1. **APP Record Configuration** – Per-record settings for A/AAAA/CNAME responses
2. **Global Address Translation Configuration** – Network group mappings and translation rules

All supported options are documented below. Unspecified parameters use default values.

## Feature 1: APP Record Network-Based Responses

This feature allows you to create **APP records** in primary and forwarder zones that return different sets of A, AAAA, or CNAME records based on the client's network.

### APP Record Setup

To respond with different records to different clients:

1. Create an **APP record** with the desired name in a primary or forwarder zone
2. Select the **Split Horizon** app
3. Choose the appropriate class:
   - **`SplitHorizon.SimpleAddress`** for A and AAAA records
   - **`SplitHorizon.SimpleCNAME`** for CNAME records

### APP Record Configuration Format

Each APP record is configured with a JSON document defining network-to-address mappings.

#### A / AAAA Record Example

```json
{
  "public": [
    "1.1.1.1",
    "2.2.2.2"
  ],
  "private": [
    "192.168.1.1",
    "::1"
  ],
  "custom-networks": [
    "172.16.1.1"
  ],
  "10.0.0.0/8": [
    "10.1.1.1"
  ]
}
```

#### CNAME Record Example

```json
{
  "public": "api.example.com",
  "private": "api.example.corp",
  "custom-networks": "custom.example.corp",
  "10.0.0.0/8": "api.intranet.example.corp"
}
```

### APP Record Configuration Keys

Keys can be one of the following:

| Key Type | Description | Example |
| --- | --- | --- |
| Network CIDR | Specific network in CIDR notation | `"10.0.0.0/8"`, `"2001:db8::/32"` |
| Named Network | Custom network name defined in global configuration | `"custom-networks"` |
| `private` | RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | `"private"` |
| `public` | All IPs outside RFC 1918 private ranges | `"public"` |

### APP Record Configuration Values

- **For A/AAAA records:** Arrays of IPv4 and IPv6 addresses
- **For CNAME records:** Single string representing the target domain

**Important:** Clients not matching any defined network are processed as if the APP record doesn't exist, falling through to other record types (e.g., FWD records).

## Feature 2: Address Translation

Translates IP addresses in DNS responses for A and AAAA requests based on the client's network address and configured 1:1 translation rules. Also supports reverse (PTR) queries for translated addresses.

This feature operates as both a **post-processor** (modifies responses before delivery) and a **request handler** (serves authoritative responses for reverse lookups).

### Global Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | Integer | `40` | App execution order when multiple apps implement `IDnsApplicationPreference` |
| `networks` | Object | `{}` | Map of custom network names to arrays of CIDR addresses |
| `enableAddressTranslation` | Boolean | `false` | Master switch to enable/disable address translation globally |
| `domainGroupMap` | Object | `{}` | Maps queried domains to named translation groups; longest matching domain takes precedence |
| `networkGroupMap` | Object | `{}` | Maps client networks (CIDR) to named translation groups |
| `groups` | Array | `[]` | Array of translation group configurations |

### Networks Configuration

The `networks` object defines named network collections that can be referenced in APP records.

**Purpose:** Centralize network definitions for reuse across multiple APP records.

**Example:**

```json
"networks": {
  "custom-networks": [
    "172.16.1.0/24",
    "172.16.10.0/24",
    "172.16.2.1"
  ],
  "branch-offices": [
    "10.100.0.0/16",
    "10.101.0.0/16"
  ]
}
```

**Formatting Rules:**

- Keys are arbitrary network names (alphanumeric and hyphens)
- Values are arrays of CIDR notation networks or individual IP addresses
- IPv4 and IPv6 addresses can be mixed

### Network Group Map Configuration

Maps client source networks to translation groups using most-specific subnet matching.

When both `domainGroupMap` and `networkGroupMap` are configured, domain-based matching takes precedence for forward A/AAAA translation. The app first looks for the longest matching domain in `domainGroupMap`; if no domain match is found, it falls back to `networkGroupMap` and then uses the most-specific network match.

**Example:**

```json
"networkGroupMap": {
  "10.0.0.0/8": "local1",
  "172.16.0.0/12": "local2",
  "192.168.0.0/16": "local3",
  "192.168.1.0/24": "local1"
}
```

**Matching Logic:**

- Client IP is matched against all configured networks
- **Most specific** (longest prefix) match wins
- Example: Client `192.168.1.10` matches `192.168.1.0/24` (local1) instead of `192.168.0.0/16` (local3)

### Translation Group Configuration

Each group in the `groups` array defines translation behavior for clients matched to that group.

#### Group Object Properties

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | String | Yes | Unique identifier matching a key in `networkGroupMap` |
| `enabled` | Boolean | No (default: true) | Enables/disables translation for this group |
| `translateReverseLookups` | Boolean | No (default: false) | Enables PTR query translation for internal IPs |
| `externalToInternalTranslation` | Object | Yes | Map of external network ranges to internal network ranges |

#### External to Internal Translation

Maps external (public) IP ranges to internal (private) IP ranges using 1:1 translation.

**Rules:**

- External and internal networks **must have the same prefix length**
- Translation replaces only the network portion of the IP address
- Host portion is preserved

**Example:**

```json
"externalToInternalTranslation": {
  "1.2.3.0/24": "10.0.0.0/24",
  "5.6.7.8/32": "10.0.0.5/32"
}
```

**Translation behavior:**

- External IP `1.2.3.4` → Internal IP `10.0.0.4`
- External IP `5.6.7.8` → Internal IP `10.0.0.5`

## Example Configuration

The following example demonstrates a complete and valid configuration using both features.

```json
{
  "networks": {
    "custom-networks": [
      "172.16.1.0/24",
      "172.16.10.0/24",
      "172.16.2.1"
    ],
    "branch-offices": [
      "10.100.0.0/16"
    ]
  },
  "enableAddressTranslation": true,
  "networkGroupMap": {
    "10.0.0.0/8": "local1",
    "172.16.0.0/12": "local2",
    "192.168.0.0/16": "local3"
  },
  "groups": [
    {
      "name": "local1",
      "enabled": true,
      "translateReverseLookups": true,
      "externalToInternalTranslation": {
        "1.2.3.0/24": "10.0.0.0/24",
        "5.6.7.8/32": "10.0.0.5/32"
      }
    },
    {
      "name": "local2",
      "enabled": true,
      "translateReverseLookups": true,
      "externalToInternalTranslation": {
        "1.2.3.4/32": "172.16.0.4/32",
        "5.6.7.8/32": "172.16.0.5/32"
      }
    },
    {
      "name": "local3",
      "enabled": true,
      "translateReverseLookups": true,
      "externalToInternalTranslation": {
        "1.2.3.4/32": "192.168.0.4/32",
        "5.6.7.8/32": "192.168.0.5/32"
      }
    }
  ]
}
```

## Network Address Formats

The app supports both IPv4 and IPv6 network specifications in CIDR notation.

### IPv4 Examples

- `192.168.1.0/24` – Standard Class C network (256 addresses)
- `10.0.0.0/8` – Entire private Class A range (16.7M addresses)
- `172.16.0.0/12` – Private Class B range (1M addresses)
- `203.0.113.0/26` – Subnet with 64 addresses
- `192.168.1.100/32` – Single host

### IPv6 Examples

- `2001:db8::/32` – Documentation prefix
- `fd00::/8` – Unique local addresses (ULA)
- `fe80::/10` – Link-local addresses
- `::/0` – All IPv6 addresses
- `2001:db8::1/128` – Single host

## How Address Translation Works

The internal processing pipeline follows these steps:

### Forward Lookups (A and AAAA Records)

1. **Query Reception and Group Matching**  
   Client source IP is matched against `networkGroupMap` using most-specific subnet matching to determine the translation group.

2. **Response Filtering**  
   Translation is applied only if:
   - Response code is `NoError`
   - Response contains at least one answer
   - Client's group has `enabled: true`

3. **IP Address Translation**  
   For each A or AAAA record in the response:
   - IP address is checked against `externalToInternalTranslation` mappings
   - If a matching external network is found, the network portion is replaced with the internal network
   - Host portion of the IP is preserved

4. **Response Delivery**  
   Modified response with translated IPs is returned to the client.

**Note:** `NXDOMAIN`, `SERVFAIL`, and `NODATA` responses are passed through unmodified.

### Reverse Lookups (PTR Records)

When `translateReverseLookups` is enabled for a group:

1. **PTR Query Detection**  
   App identifies PTR queries for domains in the `in-addr.arpa` or `ip6.arpa` namespaces.

2. **Internal IP Matching**  
   If the queried IP falls within an internal network range defined in `externalToInternalTranslation`:

3. **CNAME Response Generation**  
   App returns a CNAME record pointing to the PTR domain of the corresponding external IP.

**Example:**

- Translation rule: `"1.2.3.0/24": "10.0.0.0/24"`
- PTR query for `4.0.0.10.in-addr.arpa` (internal IP 10.0.0.4)
- Response: `CNAME 4.3.2.1.in-addr.arpa` (external IP 1.2.3.4)

## How APP Record Resolution Works

The APP record processing pipeline:

1. **Query Interception**  
   DNS query is received for a domain with an APP record configured.

2. **Client Network Identification**  
   Client source IP is extracted and evaluated against:
   - Explicit CIDR networks in the APP record configuration
   - Named networks from the global `networks` configuration
   - Special keywords (`public`, `private`)

3. **Network Matching**  
   First matching network key is selected using this priority:
   - Most specific CIDR match
   - Named network match
   - `private` or `public` match

4. **Response Generation**  
   - For **SimpleAddress**: Returns A and/or AAAA records from the matched network's address array
   - For **SimpleCNAME**: Returns CNAME record with the matched network's target domain

5. **Fallback Handling**  
   If no network matches, the APP record is ignored and processing continues with other record types (FWD, A, AAAA, etc.).

## Use Cases

### Corporate Network Segmentation

Organizations with separate internal and external DNS namespaces serve internal-only records (intranet, file servers, internal APIs) to corporate network clients while providing only public-facing records to external users.

**Configuration approach:** Use APP records with `private` and `public` keys to differentiate responses.

### VPN Split-Horizon DNS

Remote workers connecting via VPN receive internal DNS records for corporate resources, while their non-VPN traffic uses public DNS, enabling seamless access to both corporate and internet resources.

**Configuration approach:** Map VPN subnet to a named network group with internal IP responses in APP records.

### Multi-Tenant Hosting Environments

Hosting providers serve different DNS responses for the same domain based on the requesting client's network, enabling tenant isolation and customized DNS views for different customer segments.

**Configuration approach:** Define per-tenant network groups with APP records returning tenant-specific service endpoints.

### NAT Traversal and Address Translation

Organizations using external public IPs for internal resources translate public DNS responses to internal RFC 1918 addresses for clients inside the network, avoiding hairpin NAT issues.

**Configuration approach:** Enable address translation with external-to-internal mappings for each client network group.

### Geographic Load Distribution

Organizations with multiple data centers direct clients to region-specific infrastructure by serving location-appropriate DNS records based on the client's network address.

**Configuration approach:** Use named networks representing geographic regions with APP records pointing to regional service endpoints.

### Development and Staging Environments

Development teams receive DNS records pointing to staging infrastructure while production networks resolve to live systems, enabling parallel operation without namespace conflicts.

**Configuration approach:** Map development networks to staging CNAMEs, production networks to production CNAMEs in APP records.

## Troubleshooting

### APP Records Not Returning Expected Responses

**Symptoms:** Clients receive no response or unexpected IP addresses when querying domains with APP records configured.

**Diagnostic Steps:**

1. Verify the APP record exists in the zone and is configured with the correct app class (`SplitHorizon.SimpleAddress` or `SplitHorizon.SimpleCNAME`).
2. Check the client's source IP address in DNS query logs.
3. Confirm the client IP matches one of the configured network keys in the APP record JSON.
4. Validate JSON syntax using a JSON validator.
5. Test with the `public` or `private` keywords to verify basic functionality.

**Resolution:**

- Add the client's network to the APP record configuration as a CIDR range.
- Define a named network in the global `networks` configuration and reference it in the APP record.
- Ensure CIDR notation is correct (e.g., `192.168.1.0/24`, not `192.168.1.*`).
- Reload the app or restart the DNS server after configuration changes.

### Address Translation Not Applied

**Symptoms:** Clients receive external IP addresses instead of translated internal addresses in DNS responses.

**Diagnostic Steps:**

1. Verify `enableAddressTranslation` is set to `true` in the global configuration.
2. Check that the client IP matches a network in `networkGroupMap`.
3. Confirm the matched group has `enabled: true`.
4. Verify the external IP in the DNS response matches a network in `externalToInternalTranslation`.
5. Ensure external and internal networks have the same prefix length (e.g., both `/24`).

**Resolution:**

- Add the client network to `networkGroupMap` with the appropriate group name.
- Verify translation mappings use matching prefix lengths.
- Review DNS server logs for translation processing messages.
- Test with a known external IP that has a configured translation rule.

### Reverse Lookups Not Translated

**Symptoms:** PTR queries for internal IPs return NXDOMAIN or the actual internal hostname instead of the external IP's PTR record.

**Diagnostic Steps:**

1. Verify `translateReverseLookups` is set to `true` for the client's group.
2. Confirm the queried internal IP falls within a range defined in `externalToInternalTranslation`.
3. Check that the DNS server is authoritative or forwarding for the `in-addr.arpa` or `ip6.arpa` zone.
4. Review DNS query logs for PTR query processing.

**Resolution:**

- Enable `translateReverseLookups` for the appropriate group.
- Ensure the internal network range is correctly defined in the translation mapping.
- Verify PTR zone configuration in the DNS server.

### Named Networks Not Recognized in APP Records

**Symptoms:** APP records referencing named networks (e.g., `"custom-networks"`) do not match clients from those networks.

**Diagnostic Steps:**

1. Verify the named network is defined in the global `networks` configuration.
2. Check for typos in the network name (names are case-sensitive).
3. Confirm the client IP is actually within one of the CIDR ranges listed in the named network.
4. Validate JSON syntax for the `networks` object.

**Resolution:**

- Add the named network to the global configuration:

```json
"networks": {
  "custom-networks": [
    "172.16.1.0/24"
  ]
}
```

- Reload the app after modifying the global configuration.
- Use explicit CIDR notation in APP records for testing before migrating to named networks.

### Overlapping Network Ranges

**Symptoms:** Clients in overlapping network ranges receive inconsistent responses or translation behavior.

**Diagnostic Steps:**

1. Review all network definitions for overlapping CIDR ranges.
2. Check the order of networks in `networkGroupMap`.
3. Determine which network has the most specific (longest) prefix.

**Resolution:**

- Rely on most-specific subnet matching: more specific ranges (e.g., `/24`) take precedence over broader ranges (e.g., `/16`).
- Organize networks from most specific to least specific for clarity.
- Use a single catch-all range (e.g., `0.0.0.0/0`, `::/0`) for default behavior.

### Configuration Changes Not Taking Effect

**Symptoms:** Modifications to `dnsApp.config` or APP record configurations do not alter DNS resolution behavior.

**Diagnostic Steps:**

1. Validate JSON syntax using a JSON validator.
2. Check DNS server logs for configuration parsing errors.
3. Verify the app has been reloaded or the DNS server has been restarted.
4. Confirm file permissions allow the DNS server to read the configuration file.

**Resolution:**

- Validate and correct JSON syntax errors.
- Reload the app through the web console: **Apps → Split Horizon → Reload**.
- Restart the Technitium DNS Server service.
- Review application logs for specific error messages.
