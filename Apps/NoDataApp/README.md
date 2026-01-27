# No Data App

A DNS App for Technitium DNS Server that returns a NODATA response (empty answer section) for specific DNS queries while maintaining proper DNS protocol semantics.

This app provides administrators with precise control over DNS responses by intentionally returning authoritative answers with no data for configured zones or query types, useful for selective blocking, privacy enforcement, and controlled DNS behavior modification without triggering client retries or fallback mechanisms.

## Overview

The **No Data App** extends the core Technitium DNS Server functionality by intercepting DNS queries and generating RFC-compliant NODATA responses for configured domains and record types.

Key capabilities:

- **Selective NODATA responses** based on domain matching and query type filtering
- **Zone-level and query type-level granularity** for precise control
- **Authoritative response generation** preventing client fallback behavior
- **Negative caching support** with configurable TTL values
- **Simple JSON-based configuration** for rapid deployment

This app is valuable for administrators who need to suppress specific DNS responses while maintaining proper DNS protocol semantics, avoiding the negative effects of NXDOMAIN or timeout-based blocking.

## ⚠️ Important Warning: DNS Response Modification

This app modifies DNS responses for configured zones, which can affect application behavior and network connectivity.

**Operational risks:**

- Applications expecting specific record types will receive empty answers
- Services relying on affected domains may fail silently
- Troubleshooting DNS issues becomes more complex when selective NODATA is active

**Usage guidance:**

- **Option A:** Use this app for intentional response suppression in controlled environments where specific record types should not be resolved
- **Option B:** Use standard DNS blocking (NX Domain, IP blocking) if the goal is complete domain denial

**Processing order:**

This app processes queries during the DNS pipeline's post-processing phase. It takes precedence over upstream resolver responses and cache entries for configured zones.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install** or drag and drop the app package file
4. Once installed, click **Configure** to set up the app
5. Enable the app and save configuration

## Configuration

The app uses a JSON configuration file named **dnsApp.config** located in the app's installation directory.

The configuration defines one or more zones and the query types that should receive NODATA responses.

All configuration is contained within a root `zones` array.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `zones` | Array | `[]` | List of zone configuration objects defining domain matching and response behavior |

### Zone Configuration

Each zone object defines a domain pattern and the DNS query types that should receive NODATA responses.

#### Zone Object Properties

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `zone` | String | Yes | N/A | Domain name or pattern to match (supports wildcard `*` for subdomain matching) |
| `queryTypes` | Array | No | All types | List of DNS query type strings (e.g., `A`, `AAAA`, `MX`) that should receive NODATA responses |
| `ttl` | Integer | No | `60` | Time-to-live in seconds for the NODATA response negative cache |

**Example:**

```json
{
  "zones": [
    {
      "zone": "example.com",
      "queryTypes": ["A", "AAAA"],
      "ttl": 300
    }
  ]
}
```

This configuration returns NODATA for A and AAAA queries to `example.com` with a 5-minute TTL.

### Wildcard Domain Matching

The app supports wildcard patterns for subdomain matching:

**Full domain:**
```json
{
  "zone": "example.com"
}
```
Matches only `example.com`.

**Wildcard subdomain:**
```json
{
  "zone": "*.example.com"
}
```
Matches all subdomains of `example.com` (e.g., `www.example.com`, `api.example.com`) but not the apex domain.

**All subdomains including apex:**
```json
{
  "zones": [
    {
      "zone": "example.com"
    },
    {
      "zone": "*.example.com"
    }
  ]
}
```

### Query Type Filtering

If `queryTypes` is not specified, the app returns NODATA for **all** query types for the matched zone.

**Common query types:**

- `A` - IPv4 address
- `AAAA` - IPv6 address
- `MX` - Mail exchange
- `TXT` - Text record
- `CNAME` - Canonical name
- `NS` - Name server
- `PTR` - Pointer record
- `SOA` - Start of authority
- `SRV` - Service locator
- `CAA` - Certification authority authorization

**Example: Suppress only IPv6 responses**

```json
{
  "zones": [
    {
      "zone": "ipv4only.example.com",
      "queryTypes": ["AAAA"],
      "ttl": 3600
    }
  ]
}
```

This returns NODATA for AAAA queries while allowing A and other record types to resolve normally.

## Example Configuration

```json
{
  "zones": [
    {
      "zone": "tracking.example.com",
      "ttl": 300
    },
    {
      "zone": "*.ads.example.net",
      "queryTypes": ["A", "AAAA"],
      "ttl": 600
    },
    {
      "zone": "telemetry.service.local",
      "queryTypes": ["A", "AAAA", "CNAME"],
      "ttl": 86400
    },
    {
      "zone": "ipv6-blocked.example.org",
      "queryTypes": ["AAAA"],
      "ttl": 1800
    }
  ]
}
```

**Configuration behavior:**

1. **tracking.example.com**: Returns NODATA for all query types with 5-minute TTL
2. **\*.ads.example.net**: Returns NODATA for A and AAAA queries only, affecting all subdomains with 10-minute TTL
3. **telemetry.service.local**: Returns NODATA for A, AAAA, and CNAME queries with 24-hour TTL
4. **ipv6-blocked.example.org**: Returns NODATA for AAAA queries only, allowing IPv4 resolution with 30-minute TTL

## How It Works

The No Data App intercepts DNS queries during the request processing pipeline:

1. **Query Reception**: DNS server receives a client query for a specific domain and query type

2. **Zone Matching**: The app evaluates the queried domain against all configured `zone` patterns in order of definition

3. **Query Type Evaluation**: If a zone matches, the app checks if the query type is in the zone's `queryTypes` list (or matches all types if not specified)

4. **Response Generation**: If both zone and query type match, the app generates an authoritative NODATA response with:
   - Response code: `NOERROR`
   - Answer section: Empty
   - Authority section: SOA record (if applicable)
   - Additional section: Empty
   - TTL: Value from zone configuration

5. **Negative Caching**: The NODATA response is cached by both the DNS server and clients according to the configured TTL

6. **Bypass**: If no zone matches or query type is not in the filter list, the query passes through to normal DNS resolution

## Use Cases

### Privacy-Enhanced DNS Resolution

Block telemetry and tracking domains by returning NODATA responses, preventing data collection while avoiding connection timeout delays that occur with DROP-based blocking.

### IPv6 Transition Management

Temporarily suppress AAAA records for services undergoing IPv4-to-IPv6 migration, forcing clients to use IPv4 while maintaining normal DNS operation for other record types.

### Selective Service Suppression

Return NODATA for MX records on specific domains to prevent email delivery attempts while keeping other services (web, API) operational.

### Development and Testing

Create controlled DNS environments where specific record types are intentionally absent to test application fallback behavior and error handling.

### Split-Horizon DNS Enforcement

Suppress specific record types in internal networks (e.g., external MX records) while allowing resolution of other resource records for the same domain.

### Compliance and Policy Enforcement

Implement organizational policies that prohibit resolution of specific record types (e.g., SRV records for unauthorized service discovery) without completely blocking domain access.

## Troubleshooting

### NODATA responses not being returned

**Symptoms:** Queries still receive normal responses despite configuration

**Diagnostic steps:**

1. Verify the app is enabled in the Apps section
2. Check the `dnsApp.config` file syntax using a JSON validator
3. Confirm the queried domain exactly matches a configured zone pattern
4. Verify the query type is in the `queryTypes` list (if specified)
5. Review DNS server logs for app initialization errors

**Configuration checks:**

```json
{
  "zones": [
    {
      "zone": "example.com",
      "queryTypes": ["A"]
    }
  ]
}
```

Ensure `zone` values do not have trailing dots unless intended for root zone matching.

### Unexpected domains receiving NODATA responses

**Symptoms:** Domains not explicitly configured are returning empty answers

**Diagnostic steps:**

1. Review wildcard patterns in zone configuration
2. Check for overlapping zone definitions
3. Verify zone matching order (first match wins)

**Example issue:**

```json
{
  "zones": [
    {
      "zone": "*.com"
    }
  ]
}
```

This configuration affects **all** `.com` domains.

**Resolution:** Use specific zone names or subdomain patterns.

### Clients not caching NODATA responses

**Symptoms:** Repeated queries for the same domain/type despite configured TTL

**Diagnostic steps:**

1. Verify `ttl` value is set appropriately (not too low)
2. Check client resolver configuration for minimum TTL enforcement
3. Confirm DNS server is returning proper SOA record in authority section
4. Review client DNS cache settings

**Recommended TTL values:**

- Short-term blocking: `300` (5 minutes)
- Standard blocking: `3600` (1 hour)
- Long-term policy: `86400` (24 hours)

### App configuration changes not taking effect

**Symptoms:** Modified `dnsApp.config` does not change DNS responses

**Diagnostic steps:**

1. Restart the DNS App from the web console (disable and re-enable)
2. Verify configuration file was saved correctly
3. Check DNS server logs for configuration reload errors
4. Clear DNS server cache for affected zones

**Configuration reload:**

Navigate to **Apps** → **No Data App** → **Disable** → **Enable**

### SOA record missing in authority section

**Symptoms:** NODATA responses lack proper authority section

**Diagnostic steps:**

1. Verify the DNS server has authority for the configured zone
2. Check if zone is configured as authoritative in DNS server settings
3. Review zone configuration for SOA record presence

**Note:** NODATA responses for non-authoritative zones may not include SOA records, which is protocol-compliant but may affect some client behavior.

## License

This app is part of the Technitium DNS Server project.

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

For more information, visit: https://technitium.com/dns/