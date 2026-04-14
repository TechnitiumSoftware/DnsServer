# Auto PTR App

A DNS App for Technitium DNS Server that automatically generates reverse DNS (PTR) responses for both IPv4 and IPv6 addresses based on configurable domain name templates.

This app enables dynamic PTR record responses in primary and forwarder zones without manually creating individual PTR records for every IP address. It constructs PTR responses by parsing the IP address from the reverse lookup query and formatting it into a domain name using configurable prefix, suffix, and separator patterns.

## Overview

The **Auto PTR App** extends Technitium DNS Server's core functionality by providing automated PTR record generation for reverse DNS zones. Instead of maintaining extensive static PTR record sets, administrators can deploy APP records that dynamically construct responses based on the queried IP address.

**Key capabilities:**

- **Automatic PTR response generation** from reverse DNS queries (in-addr.arpa / ip6.arpa)
- **IPv4 and IPv6 support** with independent formatting rules
- **Customizable domain templates** using prefix, suffix, and IP component separators
- **Zone-level deployment** as APP records in primary or forwarder zones
- **Standards-compliant DNS behavior** including proper NODATA responses for non-PTR queries

This app is particularly valuable for environments requiring consistent, pattern-based reverse DNS naming without manual PTR record maintenance.

## Installation

1. Open the Technitium DNS Server web console.

2. Navigate to **Apps** in the main menu.

3. Click **Install App** or **Update** if a previous version exists.

4. Configure APP records in the appropriate reverse DNS zone(s).

## Configuration

Configuration is performed per APP record deployment, not at the application level. The app itself requires no global configuration file (`dnsApp.config` contains no settings).

Each APP record uses JSON-formatted data to define the PTR response template.

### APP Record Configuration Properties

When creating an APP record in a reverse DNS zone, use the following JSON structure:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `prefix` | string | `""` (empty) | Static string prepended to the generated domain name |
| `suffix` | string | `""` (empty) | Static string appended to the generated domain name (typically the domain) |
| `ipSeparator` | string | `""` (empty) | Character(s) inserted between IP address components in the domain name |

### Domain Name Construction

The app constructs PTR responses as follows:

**For IPv4 addresses:**

- Extracts the four octets from the IP address
- Converts each octet to its decimal string representation
- Joins octets using `ipSeparator`
- Prepends `prefix` and appends `suffix`

**For IPv6 addresses:**

- Extracts the 16 bytes from the IP address
- Processes bytes in pairs (16-bit words)
- Converts each pair to lowercase hexadecimal (e.g., `2001` → `2001`, `00db` → `00db`)
- Joins words using `ipSeparator`
- Prepends `prefix` and appends `suffix`

## Example Configuration

### Basic IPv4 Example

```json
{
  "prefix": "",
  "suffix": ".example.com",
  "ipSeparator": "-"
}
```

**Query:** PTR for `1.0.168.192.in-addr.arpa` (reverse of 192.168.0.1)  
**Response:** `192-168-0-1.example.com`

### IPv4 with Prefix

```json
{
  "prefix": "host-",
  "suffix": ".internal.example.net",
  "ipSeparator": "."
}
```

**Query:** PTR for `10.20.30.10.in-addr.arpa` (reverse of 10.30.20.10)  
**Response:** `host-10.30.20.10.internal.example.net`

### IPv6 Example

```json
{
  "prefix": "v6-",
  "suffix": ".ip6.example.org",
  "ipSeparator": ":"
}
```

**Query:** PTR for IPv6 reverse (e.g., 2001:db8::1)  
**Response:** `v6-2001:0db8:0000:0000:0000:0000:0000:0001.ip6.example.org`

## How It Works

The app processes reverse DNS queries through the following execution pipeline:

1. **Query Reception**: The app receives a DNS query for a name within the reverse DNS zone where the APP record is configured.

2. **Reverse Domain Parsing**: The query name (QNAME) is parsed to extract the IP address using reverse DNS notation (in-addr.arpa for IPv4, ip6.arpa for IPv6).

3. **Query Type Validation**:
   - If the query type is PTR, proceed to step 4.
   - If the query type is not PTR, return a NODATA response (NOERROR with SOA in authority section).

4. **Domain Name Generation**: The IP address is formatted into a domain name using the configured `prefix`, `ipSeparator`, and `suffix` values.

5. **Response Construction**: A DNS response is built containing a PTR record with the generated domain name and the APP record's configured TTL.

6. **Response Transmission**: The authoritative response is returned to the client with the AA (Authoritative Answer) flag set.

## Use Cases

1. **Automated reverse DNS for DHCP ranges:** Generate consistent PTR records for dynamically assigned IP addresses without manual updates.
2. **ISP customer IP reverse DNS:** Automatically provide reverse DNS for customer IP allocations using standardized naming patterns (e.g., `ip-192-0-2-1.customer.isp.example`).
3. **Internal network documentation:** Create self-documenting reverse DNS where the PTR record contains the IP address in a readable format.
4. **IPv6 deployment support:** Simplify reverse DNS management for large IPv6 allocations where manual PTR record creation is impractical.
5. **Multi-tenant hosting environments:** Provide automatic reverse DNS for hosting infrastructure using tenant identifiers in the prefix.
6. **Compliance with email server requirements:** Ensure all mail server IPs have reverse DNS records without maintaining extensive PTR record sets.

## Troubleshooting

### No PTR Response Returned

**Symptoms**: Queries to the reverse DNS zone return NXDOMAIN or no answer.

**Resolution**:

1. Verify the APP record is configured in the correct reverse DNS zone (e.g., `168.192.in-addr.arpa` for 192.168.0.0/16).
2. Ensure the APP record name covers the IP range being queried (e.g., `0.168.192.in-addr.arpa` for 192.168.0.0/24).
3. Check that the AutoPtrApp is installed and enabled in the DNS Server Apps section.
4. Review DNS query logs to confirm the query is reaching the zone.

### Malformed PTR Response

**Symptoms**: PTR responses contain unexpected characters or formatting.

**Resolution**:

1. Verify JSON configuration syntax in the APP record data field.
2. Check `ipSeparator` value for unintended characters or escape sequences.
3. Ensure `prefix` and `suffix` values do not contain invalid DNS label characters.
4. Test with minimal configuration (empty prefix/separator) to isolate the issue.

### Non-PTR Queries Return Incorrect Responses

**Symptoms**: A, AAAA, or other query types to the reverse zone return unexpected results.

**Resolution**:

- This is expected behavior. The app returns NODATA (NOERROR with SOA) for non-PTR queries.
- If other record types are needed, configure them as standard zone records, not APP records.

### IPv6 Reverse DNS Not Working

**Symptoms**: IPv6 PTR queries fail while IPv4 works correctly.

**Resolution**:

1. Verify the APP record is in the correct ip6.arpa zone (e.g., `8.b.d.0.1.0.0.2.ip6.arpa`).
2. Confirm the query is formatted as a valid IPv6 reverse DNS name.
3. Check logs for reverse domain parsing errors.
