# GeoContinentApp

A DNS App for Technitium DNS Server that provides geolocation-based DNS filtering and response customization based on the continent of origin for DNS queries.

This application extends Technitium DNS Server's core functionality by enabling administrators to define continent-specific DNS resolution policies. It allows precise control over which DNS responses are returned based on the geographic location (continent) from where the query originates, enabling geographically aware DNS infrastructure and content delivery optimization.

## Overview

**GeoContinentApp** extends the core DNS resolution pipeline by adding continent-level geographic awareness to DNS query processing.

Key capabilities include:

- **Continent-based query filtering** – Match DNS queries based on client IP geolocation to continent
- **Conditional DNS response override** – Return custom DNS responses per continent
- **Drop or block functionality** – Silently drop queries from specific continents
- **Fallback support** – Continue to next rule or default DNS resolution when no match occurs
- **Integration with MaxMind GeoIP2** – Utilizes the Technitium DNS Server's built-in geolocation database

This app is valuable for administrators managing multi-region infrastructures, content delivery networks, compliance-based geographic restrictions, or security policies requiring continent-level access control.

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** to deploy the GeoContinentApp
4. Configure the app via the **DNS Apps** configuration interface or by editing `dnsApp.config` directly

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

The app is configured using a JSON-based configuration file named **`dnsApp.config`**, located in the app's installation directory.

The configuration structure consists of global settings and continent-specific groups that define DNS resolution behavior based on the client's continent.

All configuration options must be valid JSON.

## Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | Boolean | `false` | Enables detailed logging of query matches and processing decisions |
| `groups` | Array | `[]` | Array of continent group objects defining match conditions and responses |

## Continent Groups Configuration

Each group defines a set of continents and the DNS response behavior when a query originates from one of those continents.

### Group Object Properties

| Property | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `name` | String | Yes | N/A | Human-readable identifier for the group |
| `continents` | Array | Yes | N/A | Array of continent codes (ISO 3166 two-letter codes: `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`) |
| `action` | String | Yes | N/A | Response action: `Allow`, `Drop`, or `Block` |
| `continentRecords` | Object | No | `null` | Continent-specific DNS record overrides (used when `action` is `Allow`) |

### Continent Codes

The following ISO continent codes are supported:

- `AF` – Africa
- `AN` – Antarctica
- `AS` – Asia
- `EU` – Europe
- `NA` – North America
- `OC` – Oceania
- `SA` – South America

### Actions

- **`Allow`** – Continue normal DNS resolution. If `continentRecords` is specified, return custom records.
- **`Drop`** – Silently drop the query without response.
- **`Block`** – Return a DNS block response (typically `NXDOMAIN` or blocked IP).

### Continent Records Configuration

When `action` is set to `Allow`, the `continentRecords` object can define custom DNS responses per continent.

**Structure:**

```json
"continentRecords": {
  "<ContinentCode>": {
    "A": ["<IPv4 Address>"],
    "AAAA": ["<IPv6 Address>"],
    "CNAME": ["<CNAME Target>"]
  }
}
```

**Example:**

```json
"continentRecords": {
  "EU": {
    "A": ["192.0.2.10"]
  },
  "AS": {
    "A": ["203.0.113.50"]
  }
}
```

## Example Configuration

```json
{
  "enableLogging": true,
  "groups": [
    {
      "name": "European Access",
      "continents": ["EU"],
      "action": "Allow",
      "continentRecords": {
        "EU": {
          "A": ["192.0.2.10"],
          "AAAA": ["2001:db8::10"]
        }
      }
    },
    {
      "name": "Asia-Pacific Access",
      "continents": ["AS", "OC"],
      "action": "Allow",
      "continentRecords": {
        "AS": {
          "A": ["203.0.113.50"]
        },
        "OC": {
          "A": ["198.51.100.75"]
        }
      }
    },
    {
      "name": "Block Antarctica",
      "continents": ["AN"],
      "action": "Block"
    },
    {
      "name": "Drop Africa",
      "continents": ["AF"],
      "action": "Drop"
    }
  ]
}
```

## How GeoContinentApp Works

The DNS query processing follows this execution pipeline:

1. **Query Reception** – The app intercepts the incoming DNS query before core resolution.

2. **Geolocation Lookup** – The client IP address is resolved to a continent code using the MaxMind GeoIP2 database integrated into Technitium DNS Server.

3. **Group Matching** – The app iterates through configured groups in order and checks if the resolved continent matches any group's continent list.

4. **Action Execution** – On first match:
   - **Allow**: If `continentRecords` exists for the continent, return custom DNS records. Otherwise, allow normal resolution.
   - **Drop**: Silently discard the query with no response.
   - **Block**: Return a blocked DNS response (e.g., `NXDOMAIN`).

5. **Fallback** – If no group matches, the query proceeds to standard DNS resolution.

6. **Logging** (if enabled) – Logs the matched group, continent, action, and outcome.

## Use Cases

1. **Multi-Region Content Delivery:** Route DNS queries to region-specific CDN nodes based on the continent of the user, reducing latency and improving content delivery performance.
2. **Compliance and Data Sovereignty:** Enforce geographic restrictions by blocking or redirecting DNS queries from continents where services are not legally permitted to operate.
3. **Security and Threat Mitigation:** Drop or block DNS queries originating from continents associated with elevated threat activity or abuse patterns.
4. **A/B Testing and Canary Deployments:** Redirect DNS queries from specific continents to staging or beta environments for controlled rollouts.
5. **Telecommunications and ISP Policy Enforcement:** Implement continent-based DNS filtering to enforce service availability, bandwidth policies, or regional licensing agreements.
6. **Disaster Recovery and Failover:** Redirect DNS queries from specific continents to alternate data centers during regional outages or maintenance windows.

## Troubleshooting

### Query Not Matching Expected Continent

**Symptoms:** DNS resolution does not apply the expected continent-based rule.

**Diagnostic Steps:**

1. Enable logging by setting `"enableLogging": true` in `dnsApp.config`.
2. Review the DNS Server logs to verify the detected continent for the client IP.
3. Confirm the client IP is correctly geolocated by checking the MaxMind GeoIP2 database status in the Technitium DNS Server settings.
4. Verify the continent code in the configuration matches the ISO two-letter code.

**Resolution:**

- Update the MaxMind GeoIP2 database if outdated.
- Correct any typos in continent codes.
- Ensure the client IP is public (private IPs are not geolocated).

### Custom Records Not Returned

**Symptoms:** Custom continent-specific DNS records are not returned despite `Allow` action.

**Diagnostic Steps:**

1. Verify `action` is set to `Allow`.
2. Confirm `continentRecords` is defined and contains an entry for the detected continent.
3. Check JSON syntax for errors in the `continentRecords` object.
4. Review logs to confirm the query matched the correct group.

**Resolution:**

- Ensure the continent code in `continentRecords` matches the detected continent.
- Validate JSON structure using a JSON validator.
- Restart the DNS Server app after configuration changes.

### All Queries Blocked or Dropped

**Symptoms:** Legitimate queries are unexpectedly blocked or dropped.

**Diagnostic Steps:**

1. Review group order in `dnsApp.config` – groups are evaluated sequentially.
2. Check for overly broad continent lists in early groups.
3. Verify `action` settings for each group.
4. Enable logging to trace query processing.

**Resolution:**

- Reorder groups to ensure specific rules are evaluated before general ones.
- Narrow continent lists to match intended policy.
- Adjust `action` values to match operational intent.

### Logs Not Generated

**Symptoms:** No log entries appear despite setting `"enableLogging": true`.

**Diagnostic Steps:**

1. Verify `dnsApp.config` contains `"enableLogging": true` with correct JSON syntax.
2. Confirm the DNS Server has write permissions to the log directory.
3. Restart the Technitium DNS Server service after configuration changes.

**Resolution:**

- Correct JSON syntax errors.
- Grant appropriate file system permissions.
- Check DNS Server global logging settings.

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
