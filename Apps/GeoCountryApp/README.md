# GeoCountry

A DNS App for Technitium DNS Server that provides geographic location-based DNS filtering and response customization based on the country of origin of DNS queries. This app enables administrators to implement location-aware DNS policies for access control, compliance, content delivery optimization, and regional security enforcement.

## Overview

The **GeoCountry App** extends Technitium DNS Server's core functionality by adding geographic intelligence to DNS query processing. It leverages MaxMind GeoIP2 or DB-IP databases to determine the country associated with client IP addresses and applies custom DNS policies accordingly.

**Key capabilities:**

- **Country-based DNS filtering** – Block, allow, or redirect queries based on client country
- **Geographic response customization** – Return different DNS answers for different regions
- **Access control enforcement** – Restrict domain access by geographic location
- **Compliance support** – Implement regional data residency and legal requirements
- **Flexible policy management** – Define rules using allowlists, blocklists, or group-based logic

This app is particularly valuable for organizations requiring regional content delivery, geographic access restrictions, or compliance with location-specific regulations.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and upload the GeoCountry App package
4. Configure the app through the web interface or by editing the configuration file directly

## MaxMind GeoIP2 Database Requirement

This app requires the **MaxMind GeoIP2 database** to perform geolocation lookups. A trial version (**GeoLite2**) is included with the app for evaluation purposes.

### Production Usage

For production environments, you **must purchase** the commercial **GeoIP2-Country database** from MaxMind:

**MaxMind Website:** <https://www.maxmind.com/>

The GeoLite2 database has limitations in accuracy and update frequency that may not be suitable for production workloads.

### Updating the GeoIP2 Database

To update the MaxMind GeoIP2 database used by this app:

1. Download the **GeoIP2-Country.mmdb** file from your MaxMind account
2. Create a **ZIP archive** containing the `.mmdb` file
3. In the Technitium DNS Server web console, navigate to **Apps**
4. Select **GeoContinentApp** and click **Update**
5. Use the **Manual Update** option and upload the ZIP file

### Optional: ISP/ASN Database

The app optionally supports the **MaxMind ISP/ASN database** for enhanced functionality. Update using the same method as above with the appropriate `.mmdb` file.

## Configuration

The app is configured using a JSON configuration file named **dnsApp.config** located in the app's installation directory.

All configuration is defined within a single root object containing database settings and country-based groups with associated DNS policies.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | Boolean | `true` | Enables detailed logging of country detection and policy actions |
| `databasePath` | String | (required) | Full path to the MaxMind GeoIP2 or DB-IP country database file (`.mmdb` format) |
| `groups` | Array | `[]` | Array of geographic policy groups defining country-based DNS behavior |

### Database Configuration

The app requires a MaxMind GeoIP2 Country or DB-IP Country database in MMDB format.

**Supported databases:**

- MaxMind GeoLite2 Country (free)
- MaxMind GeoIP2 Country (commercial)
- DB-IP Country (free and commercial editions)

**Example:**

```json
{
  "enableLogging": true,
  "databasePath": "/var/dns/geoip/GeoLite2-Country.mmdb"
}
```

### Group Configuration

Groups define sets of countries and the DNS actions to apply when queries originate from those countries.

Each group object supports the following properties:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | (required) | Descriptive name for the group (used in logs) |
| `countries` | Array | (required) | Array of ISO 3166-1 alpha-2 country codes (e.g., `["US", "CA", "MX"]`) |
| `action` | String | (required) | Action to perform: `"allow"`, `"block"`, `"redirect"`, or `"customResponse"` |
| `blockResponse` | String | `"REFUSED"` | DNS response code when action is `"block"`: `"REFUSED"`, `"NXDOMAIN"`, `"SERVFAIL"` |
| `redirectDomain` | String | `null` | Domain name to redirect to when action is `"redirect"` |
| `customRecords` | Array | `[]` | Array of custom DNS records to return when action is `"customResponse"` |
| `applyToZones` | Array | `[]` | Specific zones to which this group applies (empty = all zones) |
| `excludeZones` | Array | `[]` | Zones to exclude from this group policy |

**Example:**

```json
{
  "groups": [
    {
      "name": "Block High-Risk Countries",
      "countries": ["KP", "IR", "SY"],
      "action": "block",
      "blockResponse": "REFUSED"
    },
    {
      "name": "EU Content Redirection",
      "countries": ["DE", "FR", "IT", "ES", "PL"],
      "action": "redirect",
      "redirectDomain": "eu-content.example.com",
      "applyToZones": ["content.example.com"]
    }
  ]
}
```

### Custom Response Configuration

When using `"customResponse"` action, the `customRecords` array defines the DNS records to return.

Each record object supports:

| Property | Type | Description |
| --- | --- | --- |
| `type` | String | DNS record type: `"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, etc. |
| `ttl` | Integer | Time-to-live in seconds |
| `value` | String | Record data (IP address, domain name, text, etc.) |
| `priority` | Integer | Priority value (for MX records) |

**Example:**

```json
{
  "name": "APAC Custom Response",
  "countries": ["JP", "CN", "KR", "SG", "AU"],
  "action": "customResponse",
  "customRecords": [
    {
      "type": "A",
      "ttl": 300,
      "value": "203.0.113.10"
    },
    {
      "type": "AAAA",
      "ttl": 300,
      "value": "2001:db8::10"
    }
  ]
}
```

## Example Configuration

```json
{
  "enableLogging": true,
  "databasePath": "/opt/technitium/geoip/GeoLite2-Country.mmdb",
  "groups": [
    {
      "name": "Block Sanctioned Countries",
      "countries": ["KP", "IR", "SY", "CU"],
      "action": "block",
      "blockResponse": "REFUSED"
    },
    {
      "name": "EU GDPR Compliance",
      "countries": ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"],
      "action": "redirect",
      "redirectDomain": "eu-privacy.example.com",
      "applyToZones": ["app.example.com", "services.example.com"]
    },
    {
      "name": "North America CDN",
      "countries": ["US", "CA", "MX"],
      "action": "customResponse",
      "applyToZones": ["cdn.example.com"],
      "customRecords": [
        {
          "type": "A",
          "ttl": 600,
          "value": "192.0.2.100"
        },
        {
          "type": "AAAA",
          "ttl": 600,
          "value": "2001:db8:na::100"
        }
      ]
    },
    {
      "name": "Asia-Pacific CDN",
      "countries": ["JP", "CN", "KR", "SG", "AU", "NZ", "IN"],
      "action": "customResponse",
      "applyToZones": ["cdn.example.com"],
      "customRecords": [
        {
          "type": "A",
          "ttl": 600,
          "value": "203.0.113.200"
        }
      ]
    },
    {
      "name": "Default Allow",
      "countries": [],
      "action": "allow"
    }
  ]
}
```

## Supported Country Code Formats

The app uses **ISO 3166-1 alpha-2** country codes exclusively.

**Common examples:**

| Code | Country |
| ---- | ------- |
| `US` | United States |
| `GB` | United Kingdom |
| `DE` | Germany |
| `FR` | France |
| `CN` | China |
| `JP` | Japan |
| `AU` | Australia |
| `CA` | Canada |
| `BR` | Brazil |
| `IN` | India |
| `RU` | Russian Federation |

A complete list is available in the ISO 3166-1 standard documentation.

## How GeoCountry Works

The app processes DNS queries through the following pipeline:

1. **Client IP Extraction** – The app extracts the client IP address from the incoming DNS query (supports both IPv4 and IPv6)
2. **Geographic Lookup** – The client IP is queried against the configured GeoIP2/DB-IP database to determine the associated country code
3. **Group Evaluation** – Groups are evaluated in the order defined in the configuration file; the first matching group determines the action
4. **Zone Filtering** – If `applyToZones` or `excludeZones` are specified, the requested domain is checked against these lists
5. **Action Execution** – The configured action is applied:
   - **allow** – Query proceeds to normal DNS resolution
   - **block** – Configured block response is returned (REFUSED, NXDOMAIN, or SERVFAIL)
   - **redirect** – Query is rewritten to resolve the redirect domain
   - **customResponse** – Custom DNS records are returned directly
6. **Logging** – If `enableLogging` is enabled, the country detection result and action taken are recorded in the DNS server logs

## Use Cases

1. **Regional Content Delivery Optimization:** Direct users to geographically optimized CDN endpoints by returning different IP addresses based on client country, reducing latency and improving user experience.
2. **Compliance and Data Residency:** Enforce GDPR, data sovereignty, or other regulatory requirements by redirecting EU users to EU-hosted infrastructure while serving other regions from different locations.
3. **Security and Access Control:** Block DNS resolution for clients originating from high-risk countries or regions associated with malicious activity, reducing attack surface and unauthorized access attempts.
4. **Licensing and Geographic Restrictions:** Implement geographic licensing restrictions by blocking or redirecting access to services based on country of origin, supporting content distribution agreements and legal obligations.
5. **Corporate Policy Enforcement:** Restrict employee access to certain services when connecting from specific countries, supporting corporate security policies and reducing data exfiltration risks during international travel.
6. **ISP and Carrier Services** Provide differentiated DNS responses to customers based on their geographic location, enabling location-based service offerings and regional content partnerships.

## Troubleshooting

### Country Detection Not Working

**Symptoms:** All queries are treated as unknown country or default group is always matched.

**Diagnostic steps:**

1. Verify the database file exists and is readable:

   ```bash
   ls -lh /path/to/GeoLite2-Country.mmdb
   ```

2. Check file permissions:

   ```bash
   chmod 644 /path/to/GeoLite2-Country.mmdb
   ```

3. Ensure the database path in `dnsApp.config` is absolute and correct
4. Verify the database is not corrupted by checking file size (should be several MB)
5. Review DNS server logs with `enableLogging: true` to see lookup results
6. Confirm the database format is MMDB (MaxMind v2 format), not the legacy GeoIP v1 format

### Policies Not Applied to Expected Queries

**Symptoms:** DNS queries are not being blocked, redirected, or receiving custom responses as configured.

**Diagnostic steps:**

1. Verify group order in configuration – first matching group wins
2. Check `applyToZones` and `excludeZones` – policies may be scoped to specific domains
3. Confirm country codes are uppercase ISO 3166-1 alpha-2 format
4. Enable logging and review which group is matching for test queries
5. Test from known IP addresses using online GeoIP lookup tools to verify expected country detection
6. Ensure DNS queries are reaching the app (check app is enabled and loaded in DNS server)

### Incorrect Country Detection

**Symptoms:** Clients are detected as wrong country or country changes unexpectedly.

**Diagnostic steps:**

1. Verify database is up-to-date – IP address allocations change frequently
2. Download the latest version of your chosen GeoIP database
3. Check if client is using VPN, proxy, or anonymization service
4. For IPv6 queries, ensure the database supports IPv6 lookups
5. Cross-reference client IP with multiple GeoIP services to identify database accuracy issues
6. Consider using a commercial database for improved accuracy if using free edition

### Performance Degradation

**Symptoms:** DNS query response times increase after enabling GeoCountry app.

**Diagnostic steps:**

1. Verify database file is on fast local storage (not network mount)
2. Monitor server memory usage – database is loaded into memory
3. Disable logging if performance is critical and logs are not needed
4. Ensure database file is not excessively large (country databases should be <50 MB)
5. Check for disk I/O bottlenecks if database is frequently accessed from disk
6. Consider caching strategies at the application or infrastructure level

### Geolocation Database Out of Date

**Symptoms:** Queries from known IP addresses resolve to incorrect continents or no continent at all.

**Diagnostic Steps:**

1. Check the age of the current GeoIP2 database file in the app directory.
2. Verify whether you are using GeoLite2 (trial) or the commercial GeoIP2 database.
3. Review MaxMind's database update schedule and changelog.

**Resolution:**

- Download the latest **GeoIP2-Country.mmdb** from MaxMind.
- Follow the [database update procedure](#updating-the-geoip2-database) above.
- For production environments, purchase the commercial GeoIP2 database for improved accuracy and regular updates.

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
