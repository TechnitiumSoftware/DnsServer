# GeoDistance

A DNS App for Technitium DNS Server that enables geo-proximity-based DNS routing by calculating the geographical distance between client subnets and configured server locations, returning the closest endpoint(s) based on real-world geographic coordinates.

This app extends the core DNS resolution process by integrating distance-based evaluation into query responses, allowing administrators to route users to their geographically nearest infrastructure endpoint, optimizing latency and network path efficiency.

## Overview

**GeoDistance** is a DNS application that performs **geographic proximity routing** by calculating the physical distance between a DNS client's subnet and one or more configured server endpoints using latitude/longitude coordinates.

***WARNING:*** Latitude and longitude are not precise and should not be used to identify a particular street address or household.*

Key capabilities:

- **Automatic subnet detection** – Extracts client subnet from EDNS Client Subnet (ECS) or client IP
- **Haversine distance calculation** – Computes great-circle distance between client and server coordinates
- **Configurable response limits** – Returns the N closest servers or all within a threshold distance
- **Flexible endpoint sources** – Supports inline server definitions or external server group files
- **CNAME and A/AAAA responses** – Can return domain names or IP addresses based on routing decisions

This app is valuable for administrators managing geographically distributed infrastructure who need deterministic, distance-based traffic steering at the DNS layer.

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** in the main menu
3. Click **Install** or use **Upload** to install the app package
4. Once installed, configure the app via **dnsApp.config** or the web console interface

## MaxMind GeoIP2 Database Requirement

This app requires the **MaxMind GeoIP2 database** to perform geolocation lookups. A trial version (**GeoLite2**) is included with the app for evaluation purposes.

### Production Usage

For production environments, you **must purchase** the commercial **GeoIP2-City database** from MaxMind:

**MaxMind Website:** <https://www.maxmind.com/>

The GeoLite2 database has limitations in accuracy and update frequency that may not be suitable for production workloads.

### Updating the GeoIP2 Database

To update the MaxMind GeoIP2 database used by this app:

1. Download the **GeoIP2-City.mmdb** file from your MaxMind account
2. Create a **ZIP archive** containing the `.mmdb` file
3. In the Technitium DNS Server web console, navigate to **Apps**
4. Select **GeoContinentApp** and click **Update**
5. Use the **Manual Update** option and upload the ZIP file

### Optional: ISP/ASN Database

The app optionally supports the **MaxMind ISP/ASN database** for enhanced functionality. Update using the same method as above with the appropriate `.mmdb` file.

## Configuration

Configuration is stored in a JSON file named **dnsApp.config**, located in the app's installation directory.

The configuration defines:

- Geographic location of server endpoints
- Routing policies (closest N servers, distance thresholds)
- Server group references or inline server definitions

All configuration is applied per DNS query during App processing.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `servers` | array | `null` | Inline array of server objects, each containing name, domain, lat/long, and optional IP addresses |
| `serverGroupFile` | string | `null` | Path to external JSON file containing server group definitions (mutually exclusive with `servers`) |
| `closestServerCount` | integer | `1` | Number of closest servers to return in response (0 = all servers within threshold) |
| `maxDistance` | decimal | `null` | Maximum distance in kilometers; servers beyond this are excluded (optional) |

**Note:** Either `servers` or `serverGroupFile` must be specified, but not both.

### Server Object Schema

Each server object must contain:

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Human-readable identifier for the server |
| `domain` | string | Yes | Fully qualified domain name (FQDN) for the server |
| `lat` | decimal | Yes | Latitude in decimal degrees (-90.0 to 90.0) |
| `long` | decimal | Yes | Longitude in decimal degrees (-180.0 to 180.0) |
| `ipv4Addresses` | array | No | List of IPv4 addresses (optional, used for A record responses) |
| `ipv6Addresses` | array | No | List of IPv6 addresses (optional, used for AAAA record responses) |

**Example:**

```json
{
  "name": "US-East",
  "domain": "east.example.com",
  "lat": 38.9072,
  "long": -77.0369,
  "ipv4Addresses": ["192.0.2.10"],
  "ipv6Addresses": ["2001:db8::10"]
}
```

### Server Group File Format

When using `serverGroupFile`, the external JSON file must contain a root `servers` array:

```json
{
  "servers": [
    {
      "name": "EU-West",
      "domain": "eu.example.com",
      "lat": 51.5074,
      "long": -0.1278,
      "ipv4Addresses": ["203.0.113.20"]
    },
    {
      "name": "Asia-East",
      "domain": "asia.example.com",
      "lat": 35.6762,
      "long": 139.6503,
      "ipv6Addresses": ["2001:db8::30"]
    }
  ]
}
```

This allows centralized management of server groups across multiple apps or zones.

## Example Configuration

### Inline Server Configuration

```json
{
  "servers": [
    {
      "name": "US-West",
      "domain": "usw.example.com",
      "lat": 37.7749,
      "long": -122.4194,
      "ipv4Addresses": ["192.0.2.1"],
      "ipv6Addresses": ["2001:db8::1"]
    },
    {
      "name": "US-East",
      "domain": "use.example.com",
      "lat": 40.7128,
      "long": -74.0060,
      "ipv4Addresses": ["192.0.2.2"],
      "ipv6Addresses": ["2001:db8::2"]
    },
    {
      "name": "EU-Central",
      "domain": "euc.example.com",
      "lat": 50.1109,
      "long": 8.6821,
      "ipv4Addresses": ["192.0.2.3"],
      "ipv6Addresses": ["2001:db8::3"]
    }
  ],
  "closestServerCount": 2,
  "maxDistance": 5000
}
```

### External Server Group Configuration

```json
{
  "serverGroupFile": "server-groups/global-cdn.json",
  "closestServerCount": 1
}
```

## How GeoDistance Works

The app processes DNS queries through the following pipeline:

1. **Client Subnet Extraction**  
   The app retrieves the client's geographic origin from EDNS Client Subnet (ECS) if present, otherwise falls back to the direct client IP address.

2. **Geolocation Lookup**  
   The client subnet/IP is resolved to latitude/longitude coordinates using the built-in Technitium MaxMind GeoIP2 database.

3. **Distance Calculation**  
   For each configured server, the app computes the great-circle distance using the Haversine formula between client coordinates and server coordinates.

4. **Filtering and Sorting**  
   Servers exceeding `maxDistance` (if set) are excluded. Remaining servers are sorted by ascending distance.

5. **Response Construction**  
   The app returns the top N servers (defined by `closestServerCount`) as:
   - **CNAME records** (if query type is CNAME or when domain name is returned)
   - **A/AAAA records** (if IP addresses are configured and query type matches)

6. **Query Continuation**  
   The DNS server processes returned CNAME records recursively or serves A/AAAA records directly.

## Use Cases

### Global CDN / Content Distribution

Route users to the nearest edge server or PoP (Point of Presence) based on geographic proximity, reducing latency and improving user experience.

### Multi-Region SaaS Application Routing

Direct customers to the closest application cluster or database replica, ensuring compliance with data residency and optimizing response time.

### Anycast Simulation at DNS Layer

Provide anycast-like routing behavior for infrastructures that do not support BGP anycast, using DNS-based proximity steering.

### Geo-Redundant Service Failover

Return multiple geographically proximate endpoints to allow clients to fail over to nearby alternatives if the primary is unavailable.

### Regional API Gateway Load Distribution

Balance API traffic across regional gateways by directing clients to the geographically nearest ingress point.

### Latency-Optimized VPN Endpoint Selection

Assign VPN clients to the nearest tunnel endpoint based on user location, minimizing round-trip time.

## Troubleshooting

### No Response Returned / Empty Answer Section

**Symptoms:** DNS query returns NOERROR but no records.

**Diagnostics:**

- Verify that `servers` or `serverGroupFile` is correctly configured
- Check that query type matches available record types (A, AAAA, CNAME)
- Confirm that client IP/subnet resolves to valid GeoIP coordinates
- Review `maxDistance` setting – it may exclude all servers

**Resolution:**

- Ensure at least one server is within `maxDistance` (if set)
- Confirm that IP addresses are defined for A/AAAA queries
- Check DNS server logs for GeoIP lookup failures

### Incorrect Server Selected

**Symptoms:** Client is routed to a distant server instead of the nearest.

**Diagnostics:**

- Verify server latitude/longitude values are correct (use decimal degrees, not DMS)
- Confirm client IP is accurately geolocated (test with MaxMind GeoIP2 tool)
- Check if EDNS Client Subnet is being sent and parsed correctly

**Resolution:**

- Validate server coordinates using external geolocation tools
- Enable query logging to inspect ECS and calculated distances
- Update GeoIP2 database if client geolocation is stale

### App Not Processing Queries

**Symptoms:** App is installed but not invoked during query resolution.

**Diagnostics:**

- Confirm the app is enabled in DNS zone settings or global app configuration
- Verify `dnsApp.config` is valid JSON and located in the correct directory
- Check DNS server application logs for initialization errors

**Resolution:**

- Re-enable the app in the zone or global configuration
- Validate JSON syntax using a linter
- Restart the DNS server service to reload app configuration

### Server Group File Not Loaded

**Symptoms:** External server group file is ignored or causes errors.

**Diagnostics:**

- Confirm the file path in `serverGroupFile` is correct (relative or absolute)
- Check file system permissions (DNS server process must have read access)
- Validate the external JSON file syntax

**Resolution:**

- Use absolute paths if relative paths fail
- Ensure the file is readable by the DNS server process user
- Test JSON file independently with a validator

### High Query Latency

**Symptoms:** DNS responses are delayed after installing the app.

**Diagnostics:**

- Check the number of configured servers (large lists increase computation time)
- Verify GeoIP database is loaded and not corrupted
- Review server performance (CPU, disk I/O)

**Resolution:**

- Reduce the number of servers or use `maxDistance` to limit evaluation scope
- Update or rebuild GeoIP2 database
- Optimize server hardware or reduce concurrent query load

### Geolocation Database Out of Date

**Symptoms:** Queries from known IP addresses resolve to incorrect continents or no continent at all.

**Diagnostic Steps:**

1. Check the age of the current GeoIP2 database file in the app directory.
2. Verify whether you are using GeoLite2 (trial) or the commercial GeoIP2 database.
3. Review MaxMind's database update schedule and changelog.

**Resolution:**

- Download the latest **GeoIP2-City.mmdb** from MaxMind.
- Follow the [database update procedure](#updating-the-geoip2-database) above.
- For production environments, purchase the commercial GeoIP2 database for improved accuracy and regular updates.

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
