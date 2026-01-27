# Weighted Round Robin App

A DNS App for Technitium DNS Server that enables weighted load distribution across multiple DNS records based on configurable weight values, allowing administrators to control traffic distribution ratios for A, AAAA, and other record types.

This app extends the core DNS server's ability to respond with multiple records by introducing a weighted selection mechanism, ensuring that records with higher weights are returned more frequently than those with lower weights, enabling proportional traffic distribution across backend resources.

## Overview

The **Weighted Round Robin App** provides DNS-based load balancing with traffic distribution control. Unlike standard round-robin which distributes traffic equally, this app allows administrators to assign weight values to individual DNS records, controlling the proportion of queries each record receives.

**Key capabilities:**

- **Weighted record selection** based on configurable weight values (1-1000)
- **Multi-record type support** including A, AAAA, CNAME, and other DNS record types
- **Dynamic configuration** via JSON-based `dnsApp.config` file
- **Per-zone and per-record control** over traffic distribution ratios
- **Integration with Technitium DNS Server** zone management and query processing pipeline

This app is particularly valuable for administrators managing traffic distribution across geographically distributed servers, implementing blue-green deployments, or controlling traffic ratios during infrastructure transitions.

## Installation

1. Open the **Technitium DNS Server** web console in your browser

2. Navigate to **Apps** in the main menu

3. Click **Install** and either:
   - Upload the app package file, or
   - Use the built-in app store to install **Weighted Round Robin App**

4. Once installed, configure the app by editing the `dnsApp.config` file for each zone where weighted distribution is required

5. Enable the app for specific zones through the DNS Apps interface

## Configuration

The app is configured using a JSON-based configuration file named `dnsApp.config`, which must be placed within the zone directory where the app is enabled.

The configuration structure supports defining weighted records at the zone level, with each record entry specifying the DNS record type, value, and weight. The app processes these entries during query resolution to select records according to their configured weights.

All configuration options are defined below.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | Boolean | `true` | Controls whether the weighted round robin mechanism is active for this zone |
| `records` | Array | `[]` | List of weighted record objects defining the DNS records and their weights |

### Weighted Record Configuration

Each record entry in the `records` array supports the following properties:

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `name` | String | Yes | - | The fully qualified domain name (FQDN) or relative name for this record |
| `type` | String | Yes | - | DNS record type (e.g., `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`) |
| `rdata` | String | Yes | - | The record data (IP address, hostname, text value, etc.) |
| `weight` | Integer | Yes | - | Weight value from 1 to 1000; higher values increase selection probability |
| `ttl` | Integer | No | 3600 | Time to live in seconds for the DNS record |

**Example:**

```json
{
  "enabled": true,
  "records": [
    {
      "name": "www.example.com",
      "type": "A",
      "rdata": "192.168.1.10",
      "weight": 700,
      "ttl": 300
    },
    {
      "name": "www.example.com",
      "type": "A",
      "rdata": "192.168.1.20",
      "weight": 300,
      "ttl": 300
    }
  ]
}
```

In this configuration, `192.168.1.10` will be selected approximately 70% of the time, while `192.168.1.20` will be selected approximately 30% of the time.

## Weight Distribution Algorithm

The app implements a cumulative weight distribution algorithm to ensure accurate traffic ratios.

**Weight calculation:**

- Total weight is computed by summing all weights for records matching the queried name and type
- Each record is assigned a cumulative weight range proportional to its configured weight
- A random number is generated within the total weight range
- The record whose cumulative range contains the random number is selected

**Example:**

For records with weights 700, 200, and 100 (total = 1000):

- Record 1: range 0-699 (70% probability)
- Record 2: range 700-899 (20% probability)
- Record 3: range 900-999 (10% probability)

## Example Configuration

A complete configuration example for weighted load distribution across multiple data centers:

```json
{
  "enabled": true,
  "records": [
    {
      "name": "api.example.com",
      "type": "A",
      "rdata": "10.0.1.100",
      "weight": 600,
      "ttl": 300
    },
    {
      "name": "api.example.com",
      "type": "A",
      "rdata": "10.0.2.100",
      "weight": 300,
      "ttl": 300
    },
    {
      "name": "api.example.com",
      "type": "A",
      "rdata": "10.0.3.100",
      "weight": 100,
      "ttl": 300
    },
    {
      "name": "api.example.com",
      "type": "AAAA",
      "rdata": "2001:db8:1::100",
      "weight": 600,
      "ttl": 300
    },
    {
      "name": "api.example.com",
      "type": "AAAA",
      "rdata": "2001:db8:2::100",
      "weight": 400,
      "ttl": 300
    },
    {
      "name": "www.example.com",
      "type": "CNAME",
      "rdata": "cdn1.provider.com",
      "weight": 800,
      "ttl": 600
    },
    {
      "name": "www.example.com",
      "type": "CNAME",
      "rdata": "cdn2.provider.com",
      "weight": 200,
      "ttl": 600
    }
  ]
}
```

This configuration:

- Distributes IPv4 traffic to `api.example.com` at 60%, 30%, and 10% ratios across three data centers
- Distributes IPv6 traffic at 60% and 40% ratios across two data centers
- Routes 80% of `www.example.com` traffic to `cdn1.provider.com` and 20% to `cdn2.provider.com`

## Supported Record Types

The Weighted Round Robin App supports weighted distribution for the following DNS record types:

| Type | Description | Example Use Case |
|------|-------------|------------------|
| **A** | IPv4 address records | Load balancing web servers across IPv4 endpoints |
| **AAAA** | IPv6 address records | Load balancing web servers across IPv6 endpoints |
| **CNAME** | Canonical name records | Weighted distribution across CDN providers |
| **NS** | Name server records | Distributing authoritative DNS queries across name servers |
| **MX** | Mail exchange records | Weighted mail routing across mail servers |
| **TXT** | Text records | Weighted distribution of SPF, DKIM, or other TXT-based services |
| **SRV** | Service location records | Weighted service discovery for protocols using SRV records |

**Note:** For record types with priority fields (e.g., MX, SRV), the weight mechanism operates independently of the priority value. Records are first filtered by priority, then weighted distribution applies within each priority level.

## How It Works

The Weighted Round Robin App integrates into the Technitium DNS Server query processing pipeline as follows:

1. **Query Reception**: When a DNS query is received for a zone with the Weighted Round Robin App enabled, the app intercepts the query processing

2. **Record Matching**: The app identifies all configured records in `dnsApp.config` that match the queried name and type

3. **Weight Calculation**: Total weight is computed by summing all matching records' weight values

4. **Random Selection**: A cryptographically random number is generated within the range `[0, totalWeight)`

5. **Record Selection**: The app iterates through matching records in cumulative weight order, selecting the record whose cumulative range contains the random number

6. **Response Construction**: The selected record is returned in the DNS response with its configured TTL value

7. **Logging**: If query logging is enabled, the selected record and weight are recorded in the DNS server logs

This processing occurs on every query, ensuring statistical distribution according to configured weights over time.

## Use Cases

**Multi-Region Load Distribution**  
Distribute traffic across geographically distributed data centers with precise ratio control. Assign 60% of traffic to the primary region, 30% to a secondary region, and 10% to a disaster recovery site.

**Blue-Green Deployment**  
Gradually shift traffic from an existing production environment (blue) to a new environment (green). Start with 95% blue / 5% green, monitor performance, then incrementally adjust weights until achieving 100% green.

**CDN Provider Distribution**  
Balance traffic across multiple CDN providers based on cost or performance considerations. Assign 70% of traffic to a primary low-cost provider and 30% to a premium performance provider.

**Canary Releases**  
Direct a small percentage of production traffic (e.g., 5%) to a new application version while maintaining 95% on the stable version, enabling real-world testing with minimal risk exposure.

**ISP Traffic Engineering**  
Implement traffic ratios for peering relationships or transit providers. Route 80% of traffic through a primary peering connection and 20% through a backup transit link.

**Maintenance Window Preparation**  
Gradually drain traffic from servers scheduled for maintenance by reducing their weights over time, ensuring graceful traffic migration before taking systems offline.

## Troubleshooting

### Records Not Being Selected According to Configured Weights

**Symptoms**: Traffic distribution does not match configured weight ratios; some records receive significantly more or less traffic than expected.

**Diagnostic Steps**:

1. Verify that the `dnsApp.config` file is valid JSON with no syntax errors

2. Check DNS server logs for weight calculation messages:
   ```bash
   grep "Weighted Round Robin" /var/log/dns/
   ```

3. Confirm that all records for the same name and type are defined in the configuration file

4. Verify that weight values are within the valid range (1-1000)

5. Ensure the app is enabled (`"enabled": true`) in the configuration

6. Check for DNS caching at the client or intermediate resolver level, which may mask weight distribution over short observation periods

**Resolution**: Weight distribution is statistical and requires a sufficient sample size. Monitor queries over at least 1000 requests to verify distribution accuracy.

### App Not Responding to Queries

**Symptoms**: DNS queries are not being processed by the Weighted Round Robin App; standard DNS responses are returned instead.

**Diagnostic Steps**:

1. Verify the app is installed and enabled in the DNS Apps interface

2. Confirm the `dnsApp.config` file exists in the correct zone directory

3. Check file permissions on `dnsApp.config`:
   ```bash
   ls -l /etc/dns/zones/<zonename>/dnsApp.config
   ```

4. Review DNS server logs for app initialization errors:
   ```bash
   journalctl -u dns-server | grep -i "weighted"
   ```

5. Verify zone configuration allows app integration

**Resolution**: Restart the DNS server service after configuration changes to ensure the app reloads the configuration file.

### Weight Changes Not Taking Effect

**Symptoms**: Modifications to weight values in `dnsApp.config` do not change traffic distribution.

**Diagnostic Steps**:

1. Verify the configuration file was saved after editing

2. Check the file modification timestamp:
   ```bash
   stat /etc/dns/zones/<zonename>/dnsApp.config
   ```

3. Restart the DNS server or reload the zone configuration

4. Clear DNS caches on clients and intermediate resolvers

**Resolution**: The app reads configuration on initialization. After modifying `dnsApp.config`, restart the DNS server service or use the web console to reload the zone configuration.

### High Weight Values Not Producing Expected Ratios

**Symptoms**: Records with very high weights (e.g., 900+) still receive less traffic than expected.

**Diagnostic Steps**:

1. Verify total weight calculation across all matching records

2. Check for duplicate record entries in the configuration file

3. Ensure record names and types match exactly (including trailing dots for FQDNs)

4. Review query logs to confirm which records are being matched

**Resolution**: Weight ratios are relative to total weight. A record with weight 900 among records with total weight 1000 receives 90% of traffic, but the same record among total weight 10000 receives only 9%.

## License

This app is part of the **Technitium DNS Server** project.

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

For more information, visit: https://github.com/TechnitiumSoftware/DnsServer