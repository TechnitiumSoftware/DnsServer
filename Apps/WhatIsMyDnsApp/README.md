# WhatIsMyDns

A DNS App for Technitium DNS Server that returns the client's IP address, geolocation, and network information in response to DNS queries. This app enables DNS-based client identification and IP diagnostics, making it useful for network troubleshooting, geolocation services, and client information disclosure.

## Overview

**WhatIsMyDns** extends the core DNS server functionality by intercepting queries to a designated domain and responding with the client's own network information encoded in DNS records. Instead of performing standard DNS resolution, the app returns the querying client's IP address and associated metadata through TXT, A, or AAAA records.

Key capabilities:

- **Client IP disclosure** via A/AAAA records containing the client's source address
- **Geolocation data** including country, region, city, and coordinates via TXT records
- **ISP and ASN information** identifying the client's network provider
- **Multiple query format support** including standard queries and special subdomains for specific data
- **MaxMind GeoIP2 integration** for accurate location and network intelligence

This app is particularly valuable for network administrators performing connectivity diagnostics, security researchers analyzing DNS client behavior, and service providers offering IP geolocation services.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and upload the app package
4. Enable the app and configure the designated domain in `dnsApp.config`

## Configuration

The app is configured via the `dnsApp.config` file located in the app's installation directory. The configuration defines which domains trigger the WhatIsMyDns response behavior and how geolocation data is accessed.

All configuration must be valid JSON format.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `domain` | string | `""` | The domain name that triggers WhatIsMyDns responses. Queries to this domain and its subdomains return client information. |
| `geoIpCityDatFile` | string | `null` | Absolute file path to the MaxMind GeoIP2 City database (.mmdb file). If not specified, geolocation features are disabled. |

### Domain Configuration

The `domain` property specifies the authoritative zone for which this app will respond with client information. When a client queries this domain or any subdomain, the app intercepts the query and returns the client's network data instead of performing standard resolution.

**Example:**

```json
{
  "domain": "ip.example.com",
  "geoIpCityDatFile": "/var/lib/technitium/GeoLite2-City.mmdb"
}
```

In this configuration, any query to `ip.example.com` or `*.ip.example.com` will trigger client information responses.

### GeoIP Database Configuration

The `geoIpCityDatFile` property must point to a valid MaxMind GeoIP2 or GeoLite2 City database file. This binary database enables the app to translate IP addresses into geographic and network metadata.

**Obtaining GeoIP2 Database:**

1. Create a free MaxMind account at https://www.maxmind.com/
2. Download the GeoLite2 City database in MMDB format
3. Place the file in a persistent location accessible to the DNS server
4. Specify the absolute path in the configuration

**Note:** The GeoLite2 databases require periodic updates to maintain accuracy. Administrators should implement automated update procedures.

## Query Formats

The app supports multiple query formats to retrieve different types of client information:

### Standard Query

**Query:** `<domain>` or `www.<domain>`

**Response:** 
- **A/AAAA Record:** Returns the client's IPv4 or IPv6 address
- **TXT Record:** Returns comprehensive information including IP, location, ISP, and coordinates

**Example:**

```bash
dig @dns-server ip.example.com A
dig @dns-server ip.example.com TXT
```

### Subdomain Query Formats

The app recognizes special subdomain prefixes to return specific data elements:

**Query:** `<data-type>.<domain>`

**Supported data types:**

- `ip` - Returns only the client's IP address
- `country` - Returns ISO country code
- `region` - Returns region/state name
- `city` - Returns city name
- `lat` - Returns latitude coordinate
- `long` - Returns longitude coordinate
- `isp` - Returns ISP/organization name
- `asn` - Returns Autonomous System Number

**Example:**

```bash
dig @dns-server country.ip.example.com TXT
# Returns: "US"

dig @dns-server isp.ip.example.com TXT
# Returns: "Example Communications LLC"
```

## Example Configuration

```json
{
  "domain": "whatismyip.local",
  "geoIpCityDatFile": "/opt/technitium/geoip/GeoLite2-City.mmdb"
}
```

This configuration establishes `whatismyip.local` as the diagnostic domain with full geolocation capabilities enabled through the GeoLite2 City database.

## Supported Response Record Types

### A Record (IPv4)

Returns the client's IPv4 address when the client uses IPv4 transport or when explicitly queried.

**Example Response:**
```
whatismyip.local. 60 IN A 203.0.113.45
```

### AAAA Record (IPv6)

Returns the client's IPv6 address when the client uses IPv6 transport or when explicitly queried.

**Example Response:**
```
whatismyip.local. 60 IN AAAA 2001:db8::1234:5678
```

### TXT Record (Full Information)

Returns a comprehensive text record containing all available client information in key-value format.

**Example Response:**
```
whatismyip.local. 60 IN TXT "IP=203.0.113.45; Country=US; Region=California; City=San Francisco; Lat=37.7749; Long=-122.4194; ISP=Example ISP Inc; ASN=AS15169"
```

**Format:** The TXT record uses semicolon-separated key-value pairs. Missing data elements are omitted from the response.

## How It Works

The WhatIsMyDns app operates through the following processing pipeline:

1. **Query Interception** - The app registers as the authoritative handler for the configured domain. When a DNS query matches the domain or any subdomain, processing is handed to the app.

2. **Client Identification** - The app extracts the client's source IP address from the DNS query metadata provided by the Technitium DNS Server core.

3. **Subdomain Parsing** - If the query contains subdomain labels, the app parses them to determine if a specific data element is requested (e.g., `country`, `isp`).

4. **GeoIP Lookup** - If the GeoIP2 database is configured, the app performs a lookup of the client IP address to retrieve geolocation and network information.

5. **Response Construction** - Based on the query type (A, AAAA, TXT) and any subdomain filters, the app constructs the appropriate DNS response:
   - A/AAAA queries return the client IP in address record format
   - TXT queries return formatted text with all available data
   - Subdomain queries return only the requested data element

6. **Response Transmission** - The constructed response is returned to the client with a 60-second TTL, indicating the information is time-sensitive.

## Use Cases

**Network Connectivity Diagnostics**  
System administrators can direct users to query the WhatIsMyDns domain to confirm their public IP address, verify NAT traversal, and validate IPv4/IPv6 connectivity. This eliminates the need for external HTTP-based "what is my IP" services.

**Geolocation Service Provision**  
Service providers can offer DNS-based geolocation lookups for applications that need to determine client location without HTTP dependencies. This is particularly useful for embedded systems and IoT devices with DNS-only networking stacks.

**ISP and Network Intelligence**  
Security operations teams can use the ISP and ASN information to quickly identify the network origin of DNS queries, enabling rapid classification of traffic sources during incident response.

**Split-Tunnel VPN Verification**  
End users can verify VPN operation by querying the WhatIsMyDns domain before and after VPN connection. Changes in the returned IP, country, or ISP data confirm successful VPN tunnel establishment.

**Automated IP Address Discovery**  
Scripts and automation tools can perform simple DNS TXT queries to discover the system's public IP address without requiring HTTP client libraries or parsing HTML responses.

**DNS Client Testing**  
DNS software developers can use WhatIsMyDns to verify that their client implementations correctly handle various record types and properly expose source address information to upstream resolvers.

## Troubleshooting

### GeoIP Data Not Appearing in TXT Records

**Symptoms:** TXT record responses contain only IP address without location, ISP, or ASN data.

**Diagnostic Steps:**

1. Verify the `geoIpCityDatFile` path is correct and the file exists:
   ```bash
   ls -l /path/to/GeoLite2-City.mmdb
   ```

2. Check file permissions - the Technitium DNS Server process must have read access to the .mmdb file

3. Review the DNS server application logs for GeoIP initialization errors

4. Confirm the database file is a valid MaxMind GeoIP2/GeoLite2 City database (not Country or ASN-only)

5. Test with a known public IP address - private/internal addresses will not have geolocation data

**Resolution:** Correct the file path in `dnsApp.config`, adjust file permissions to grant read access, or download a fresh database file.

### Queries Return NXDOMAIN

**Symptoms:** Queries to the configured domain return NXDOMAIN (non-existent domain) responses.

**Diagnostic Steps:**

1. Verify the app is enabled in the Technitium DNS Server Apps interface

2. Confirm the `domain` property in `dnsApp.config` exactly matches the queried domain

3. Check that no conflicting zone exists in the DNS server's zone configuration - the app domain must not be configured as a standard zone

4. Review the DNS server query logs to confirm queries are reaching the server

5. Restart the DNS server application to ensure configuration changes are loaded

**Resolution:** Enable the app, correct the domain configuration, remove conflicting zones, or reload the app configuration.

### IPv6 Addresses Not Returned for IPv6 Clients

**Symptoms:** IPv6 clients receive IPv4 addresses in A records instead of their IPv6 address in AAAA records.

**Diagnostic Steps:**

1. Verify the query is explicitly for AAAA record type:
   ```bash
   dig @dns-server whatismyip.local AAAA
   ```

2. Confirm the client is actually using IPv6 transport to reach the DNS server - check server listening addresses

3. Review DNS server transport logs to determine which protocol the query arrived on

4. Test from a known IPv6-only network segment

**Resolution:** Ensure AAAA queries are used for IPv6 responses, or verify IPv6 connectivity between client and DNS server.

### Subdomain Queries Return Empty TXT Records

**Symptoms:** Queries like `country.whatismyip.local` return empty TXT records or NODATA responses.

**Diagnostic Steps:**

1. Verify GeoIP database is properly configured (subdomain queries require geolocation data)

2. Confirm the queried subdomain matches a supported data type (`ip`, `country`, `region`, `city`, `lat`, `long`, `isp`, `asn`)

3. Check that the client IP address has data available in the GeoIP database (query the root domain to see all available data)

4. Review spelling of subdomain labels - they are case-insensitive but must match exactly

**Resolution:** Configure GeoIP database, correct subdomain labels, or verify the client IP has geolocation data available.

## License

This app is part of the Technitium DNS Server project.

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

For full license terms, see https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE