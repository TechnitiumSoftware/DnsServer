# WildIp App

A DNS App for Technitium DNS Server that enables wildcard IP address resolution by dynamically generating DNS responses containing IP addresses derived from subdomain labels. This app allows you to create DNS zones where the IP address is encoded directly in the hostname, supporting both IPv4 and IPv6 addresses with flexible encoding formats.

## Overview

WildIp extends the core DNS server functionality by **intercepting DNS queries and dynamically generating A or AAAA records** based on patterns embedded in the queried domain name. Rather than maintaining static zone files, the app parses the subdomain structure to extract IP addresses encoded using various formats (dash-separated, hexadecimal, or custom separators).

**Key capabilities:**

- **Dynamic IPv4 and IPv6 resolution** from subdomain labels
- **Multiple encoding format support** including dash-separated (`192-168-1-1`), hex (`c0a80101`), and custom separators
- **Flexible zone configuration** with pattern matching and validation
- **TTL and response customization** per zone
- **Reverse DNS (PTR) support** for dynamically generated addresses

This app provides administrators with a powerful tool for creating dynamic DNS testing environments, IP-based service routing, and simplified DNS-based IP addressing schemes without maintaining extensive zone files.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and upload the WildIp app package
4. Configure the app using the `dnsApp.config` file as described below

## Configuration

The app is configured through a JSON file named **`dnsApp.config`** located in the app's installation directory.

The configuration consists of a root object containing global settings and an array of zone definitions. Each zone specifies the domain pattern, IP format, and response behavior.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `zones` | Array | `[]` | Array of zone configuration objects defining wildcard IP patterns |

### Zone Configuration

Each zone object in the `zones` array defines a wildcard IP pattern for a specific domain.

#### Zone Object Properties

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `zone` | String | *Required* | The DNS zone name (e.g., `ip.example.com`) where wildcard IP resolution applies |
| `ipv4Format` | String | `"dash"` | Format for encoding IPv4 addresses. Options: `"dash"`, `"hex"`, or a custom separator character |
| `ipv6Format` | String | `"dash"` | Format for encoding IPv6 addresses. Options: `"dash"`, `"hex"`, or a custom separator character |
| `ttl` | Integer | `300` | Time-To-Live (in seconds) for generated DNS responses |
| `soaSerial` | Integer | `1` | SOA record serial number for the zone |
| `soaRefresh` | Integer | `3600` | SOA refresh interval in seconds |
| `soaRetry` | Integer | `900` | SOA retry interval in seconds |
| `soaExpire` | Integer | `604800` | SOA expire time in seconds |
| `soaMinimum` | Integer | `300` | SOA minimum TTL in seconds |
| `soaPrimaryNameServer` | String | `"ns.example.com"` | SOA primary name server hostname |
| `soaResponsiblePerson` | String | `"admin.example.com"` | SOA responsible person email (in DNS format) |

### IPv4 Format Options

The `ipv4Format` property controls how IPv4 addresses are encoded in subdomains:

- **`"dash"`**: Octets separated by dashes (e.g., `192-168-1-1.ip.example.com` → `192.168.1.1`)
- **`"hex"`**: Hexadecimal representation without separators (e.g., `c0a80101.ip.example.com` → `192.168.1.1`)
- **Custom separator**: Any single character (e.g., `"_"` for `192_168_1_1.ip.example.com` → `192.168.1.1`)

### IPv6 Format Options

The `ipv6Format` property controls how IPv6 addresses are encoded in subdomains:

- **`"dash"`**: Hextets separated by dashes (e.g., `2001-db8-0-0-0-0-0-1.ip.example.com` → `2001:db8::1`)
- **`"hex"`**: Full 32-character hexadecimal without separators (e.g., `20010db8000000000000000000000001.ip.example.com` → `2001:db8::1`)
- **Custom separator**: Any single character (e.g., `"_"` for IPv6 hextets)

## Example Configuration

````json
{
  "zones": [
    {
      "zone": "ip.example.com",
      "ipv4Format": "dash",
      "ipv6Format": "dash",
      "ttl": 300,
      "soaSerial": 1,
      "soaRefresh": 3600,
      "soaRetry": 900,
      "soaExpire": 604800,
      "soaMinimum": 300,
      "soaPrimaryNameServer": "ns.example.com",
      "soaResponsiblePerson": "admin.example.com"
    },
    {
      "zone": "hex.example.com",
      "ipv4Format": "hex",
      "ipv6Format": "hex",
      "ttl": 600,
      "soaSerial": 1,
      "soaRefresh": 7200,
      "soaRetry": 1800,
      "soaExpire": 1209600,
      "soaMinimum": 600,
      "soaPrimaryNameServer": "ns.example.com",
      "soaResponsiblePerson": "hostmaster.example.com"
    },
    {
      "zone": "custom.example.com",
      "ipv4Format": "_",
      "ipv6Format": "-",
      "ttl": 60,
      "soaSerial": 2,
      "soaRefresh": 1800,
      "soaRetry": 600,
      "soaExpire": 86400,
      "soaMinimum": 60,
      "soaPrimaryNameServer": "dns1.example.com",
      "soaResponsiblePerson": "dnsadmin.example.com"
    }
  ]
}
````

## Supported IPv4 Formats

### Dash-Separated Format

**Format**: `<octet1>-<octet2>-<octet3>-<octet4>.<zone>`

**Example**: `192-168-1-100.ip.example.com` → `192.168.1.100`

Each octet must be a valid decimal number between 0 and 255.

### Hexadecimal Format

**Format**: `<8-hex-digits>.<zone>`

**Example**: `c0a80164.ip.example.com` → `192.168.1.100`

The hexadecimal string must be exactly 8 characters representing the 32-bit IPv4 address. Leading zeros are required.

### Custom Separator Format

**Format**: `<octet1><sep><octet2><sep><octet3><sep><octet4>.<zone>`

**Example** (using underscore): `192_168_1_100.ip.example.com` → `192.168.1.100`

Any single character can be configured as the separator.

## Supported IPv6 Formats

### Dash-Separated Format

**Format**: `<hextet1>-<hextet2>-...-<hextet8>.<zone>`

**Example**: `2001-0db8-0000-0000-0000-0000-0000-0001.ip.example.com` → `2001:db8::1`

Each hextet is a 1-4 character hexadecimal group. Zero compression is applied in the response.

### Hexadecimal Format

**Format**: `<32-hex-digits>.<zone>`

**Example**: `20010db8000000000000000000000001.ip.example.com` → `2001:db8::1`

The hexadecimal string must be exactly 32 characters representing the full 128-bit IPv6 address.

### Custom Separator Format

**Format**: `<hextet1><sep><hextet2><sep>...<sep><hextet8>.<zone>`

**Example** (using underscore): `2001_db8_0_0_0_0_0_1.ip.example.com` → `2001:db8::1`

## How WildIp Works

The app processes DNS queries through the following pipeline:

1. **Query Reception**: The DNS server receives a query (A, AAAA, or PTR) and passes it to the WildIp app

2. **Zone Matching**: The app checks if the queried domain matches any configured zone in the `zones` array

3. **Label Extraction**: If a match is found, the app extracts the leftmost subdomain label containing the encoded IP address

4. **Format Detection and Parsing**: Based on the configured format (`ipv4Format` or `ipv6Format`), the app parses the label:
   - For dash format: splits by dash and validates octets/hextets
   - For hex format: validates length and converts from hexadecimal
   - For custom separator: splits by the specified character

5. **IP Address Validation**: The parsed components are validated to ensure they form a valid IP address

6. **Response Generation**: If validation succeeds, the app generates:
   - **A record** for IPv4 queries
   - **AAAA record** for IPv6 queries
   - **PTR record** for reverse lookups (if the query matches the pattern)
   - **SOA record** for authority information

7. **Response Return**: The generated DNS response is returned with the configured TTL

8. **Failure Handling**: If parsing or validation fails, the app returns no records and allows other DNS processing to continue

## Use Cases

**Dynamic Testing Environments**: Create DNS-based test infrastructure where developers can query arbitrary IP addresses without pre-configuring zone files (e.g., `10-0-0-5.test.example.com` for testing connectivity to `10.0.0.5`).

**IP-Based Service Routing**: Enable applications to discover service endpoints by encoding IP addresses in DNS names, useful for microservices communication or dynamic load balancing without maintaining service registries.

**Network Diagnostics and Troubleshooting**: Provide network administrators with a quick DNS-based IP resolution tool for testing connectivity, DNS propagation, or validating firewall rules without modifying DNS zones.

**Educational and Training Labs**: Deploy simplified DNS environments for training purposes where students can experiment with DNS resolution without understanding complex zone file syntax.

**Development and CI/CD Pipelines**: Allow automated testing frameworks to dynamically resolve test endpoints by encoding target IPs in hostnames, eliminating the need for environment-specific DNS configuration.

**Multi-Tenant IP Isolation**: Create tenant-specific IP addressing schemes where each tenant's services are accessible via encoded DNS names, simplifying network segmentation and access control.

## Troubleshooting

### No Response for Wildcard Queries

**Symptoms**: Queries to domains like `192-168-1-1.ip.example.com` return NXDOMAIN or no response.

**Diagnostic Steps**:

1. Verify the zone is correctly configured in `dnsApp.config` and matches the queried domain
2. Check the Technitium DNS Server logs for parsing errors or validation failures
3. Confirm the IP format matches the configured `ipv4Format` or `ipv6Format`
4. Test with a simple, known-valid IP pattern (e.g., `1-1-1-1.ip.example.com`)

**Configuration Check**:

```json
{
  "zones": [
    {
      "zone": "ip.example.com",
      "ipv4Format": "dash"
    }
  ]
}
```

Ensure the `zone` property exactly matches the base domain being queried.

### Invalid IP Address Parsing

**Symptoms**: Queries fail or return unexpected results for hexadecimal or custom separator formats.

**Diagnostic Steps**:

1. Verify the encoded IP uses the correct number of characters for hex format (8 for IPv4, 32 for IPv6)
2. Check that custom separators match the configured character exactly
3. Validate that octet/hextet values are within valid ranges (0-255 for IPv4 octets)
4. Review DNS server logs for specific parsing error messages

**Example Validation**:

For IPv4 hex format, `c0a80101` (8 characters) is valid, but `c0a801` (6 characters) is not.

### SOA Record Issues

**Symptoms**: Zone authority queries fail or return incorrect SOA information.

**Diagnostic Steps**:

1. Verify all SOA-related properties are configured: `soaPrimaryNameServer`, `soaResponsiblePerson`, `soaSerial`, etc.
2. Ensure `soaPrimaryNameServer` and `soaResponsiblePerson` are valid FQDNs
3. Check that SOA timing values (refresh, retry, expire, minimum) are appropriate for your use case

**Configuration Check**:

```bash
dig @dns-server-ip ip.example.com SOA
```

The response should contain the configured SOA record with correct values.

### TTL Not Applied Correctly

**Symptoms**: DNS responses show unexpected Time-To-Live values.

**Diagnostic Steps**:

1. Verify the `ttl` property is set in the zone configuration
2. Check if downstream DNS resolvers or caching layers are overriding TTL values
3. Use `dig` to inspect the actual TTL in responses:

```bash
dig @dns-server-ip 192-168-1-1.ip.example.com A
```

Look for the TTL value in the ANSWER section (second column).

### App Not Loading or Crashing

**Symptoms**: WildIp app shows as inactive or DNS server logs show app initialization errors.

**Diagnostic Steps**:

1. Verify `dnsApp.config` contains valid JSON syntax (use a JSON validator)
2. Check that all required properties are present in each zone configuration
3. Review Technitium DNS Server application logs for detailed error messages
4. Ensure the app package is compatible with the installed DNS server version

**Configuration Validation**:

Test JSON syntax using:

```bash
cat dnsApp.config | python3 -m json.tool
```

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
