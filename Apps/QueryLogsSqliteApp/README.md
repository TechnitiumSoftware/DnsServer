# Query Logs SQLite App

A DNS App for Technitium DNS Server that provides high-performance local query logging using SQLite databases with automatic rotation, retention policies, and flexible querying capabilities.

This application extends the core DNS Server's logging functionality by offering a lightweight, file-based storage solution for DNS query logs. It enables administrators to maintain historical DNS query data with configurable retention periods, automatic database rotation, and efficient query mechanisms without requiring external database infrastructure.

## Overview

The **Query Logs SQLite App** extends Technitium DNS Server by intercepting DNS query events and persisting them to local SQLite database files. 

**Core capabilities:**

- **Automatic database rotation** based on configurable intervals (hourly, daily, weekly, monthly)
- **Retention policy enforcement** with automatic cleanup of aged database files
- **Query-time filtering** by client IP, domain name, record type, and time range
- **Protocol and response metadata** including RCODE, query type, and answer records
- **Low-overhead operation** using indexed SQLite schema for efficient retrieval
- **No external dependencies** beyond the .NET SQLite provider

This application is particularly valuable for administrators requiring persistent DNS audit trails, security investigations, compliance reporting, and traffic analysis without deploying centralized logging infrastructure.

## Installation

1. Open the Technitium DNS Server web console and authenticate with administrative credentials

2. Navigate to **Apps** in the main menu

3. Click **Install** or **Update** (if upgrading an existing installation)

4. Locate **Query Logs SQLite App** in the application catalog and confirm installation

5. Configure the application using the **dnsApp.config** file or through the web console interface

## Configuration

The application is configured through the **dnsApp.config** JSON file located in the application's installation directory.

The configuration defines database storage paths, rotation intervals, retention policies, and operational parameters. All configuration properties are optional and will use documented defaults if not specified.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | Boolean | `true` | Master switch to enable or disable query logging |
| `logFolderPath` | String | `logs` | Relative or absolute path to directory where SQLite database files are stored |
| `rotationInterval` | String | `Daily` | Database rotation frequency: `Hourly`, `Daily`, `Weekly`, `Monthly` |
| `maxLogFileDays` | Integer | `30` | Number of days to retain database files before automatic deletion |
| `useUtc` | Boolean | `false` | Store timestamps in UTC when `true`, local time when `false` |
| `maxDatabaseSizeMB` | Integer | `500` | Maximum size in megabytes for a single database file before forced rotation |
| `logQueryErrors` | Boolean | `false` | Include queries that resulted in DNS errors (SERVFAIL, NXDOMAIN, etc.) |

### Database Schema

The application creates SQLite databases with the following schema:

#### Table: `query_logs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing unique identifier |
| `timestamp` | TEXT | ISO 8601 timestamp of query reception |
| `clientIp` | TEXT | Source IP address of DNS client |
| `protocol` | TEXT | Transport protocol: `UDP`, `TCP`, `HTTPS`, `TLS` |
| `queryType` | TEXT | DNS record type requested (A, AAAA, MX, etc.) |
| `queryName` | TEXT | Fully qualified domain name queried |
| `rcode` | TEXT | DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.) |
| `answer` | TEXT | Serialized JSON array of answer records |

**Indexes:**

- `idx_timestamp` on `timestamp` column
- `idx_clientIp` on `clientIp` column  
- `idx_queryName` on `queryName` column
- `idx_queryType` on `queryType` column

These indexes optimize common query patterns for time-based searches, client filtering, and domain lookups.

### Database File Naming

Database files are named according to the rotation interval and timestamp:

- **Hourly**: `queries_2026-01-26_14.db`
- **Daily**: `queries_2026-01-26.db`
- **Weekly**: `queries_2026-W04.db`
- **Monthly**: `queries_2026-01.db`

This naming convention allows for efficient retention policy enforcement and human-readable file identification.

## Example Configuration

```json
{
  "enableLogging": true,
  "logFolderPath": "/var/dns/query-logs",
  "rotationInterval": "Daily",
  "maxLogFileDays": 90,
  "useUtc": true,
  "maxDatabaseSizeMB": 1000,
  "logQueryErrors": true
}
```

This configuration enables logging with daily rotation, 90-day retention, UTC timestamps, 1GB maximum database size, and includes error responses in the logs.

## How Query Logging Works

The Query Logs SQLite App operates through the following execution pipeline:

1. **Query Interception**: The DNS Server invokes the app's post-resolution hook after processing each DNS query

2. **Configuration Check**: The `enableLogging` flag is evaluated; if disabled, processing terminates immediately

3. **Database Selection**: The current timestamp is evaluated against the rotation interval to determine the target database file path

4. **Database Initialization**: If the target database does not exist, it is created with the defined schema and indexes

5. **Record Insertion**: Query metadata (timestamp, client IP, protocol, query type, domain, RCODE, answers) is inserted via parameterized SQL statement

6. **Rotation Enforcement**: If `maxDatabaseSizeMB` is exceeded, a new database is created according to the next rotation interval

7. **Retention Cleanup**: Background process periodically scans `logFolderPath` and deletes database files older than `maxLogFileDays`

8. **Transaction Commit**: Changes are committed to disk with SQLite's default durability settings

This pipeline executes asynchronously to minimize impact on DNS query response times.

## Use Cases

**Security Incident Investigation**  
After detecting suspicious network activity, administrators can query historical DNS logs to identify malicious domains, command-and-control servers, or data exfiltration attempts by correlating client IP addresses with queried domain names.

**Compliance and Audit Reporting**  
Organizations subject to regulatory requirements (GDPR, HIPAA, PCI-DSS) can maintain verifiable DNS query records for specified retention periods, enabling compliance audits and forensic analysis.

**Network Traffic Analysis**  
Network operations teams can analyze DNS query patterns to identify bandwidth consumption trends, detect misconfigured clients repeatedly querying non-existent domains, or discover shadow IT services through unusual domain lookups.

**Capacity Planning**  
By retaining query logs over extended periods, administrators can analyze query volume trends, peak usage times, and protocol distribution to inform infrastructure scaling decisions.

**Troubleshooting Client Connectivity**  
When investigating client connectivity issues, logs can reveal whether DNS resolution is functioning correctly, identify timeout patterns, or expose incorrect DNS client configurations.

**Threat Intelligence Integration**  
Historical query logs can be cross-referenced with threat intelligence feeds to identify previously unknown indicators of compromise (IoCs) present in past network traffic.

## Querying Logged Data

While the application does not provide a built-in query interface, administrators can use standard SQLite tools to analyze logged data.

### Using SQLite Command-Line Interface

```bash
sqlite3 /var/dns/query-logs/queries_2026-01-26.db
```

**Example Queries:**

**Retrieve all queries from a specific client:**
```sql
SELECT timestamp, queryName, queryType, rcode 
FROM query_logs 
WHERE clientIp = '192.168.1.100' 
ORDER BY timestamp DESC;
```

**Find all queries for a specific domain:**
```sql
SELECT timestamp, clientIp, protocol, rcode 
FROM query_logs 
WHERE queryName LIKE '%example.com' 
ORDER BY timestamp DESC;
```

**Analyze query type distribution:**
```sql
SELECT queryType, COUNT(*) as count 
FROM query_logs 
GROUP BY queryType 
ORDER BY count DESC;
```

**Identify clients with most queries:**
```sql
SELECT clientIp, COUNT(*) as query_count 
FROM query_logs 
GROUP BY clientIp 
ORDER BY query_count DESC 
LIMIT 10;
```

**Find all NXDOMAIN responses:**
```sql
SELECT timestamp, clientIp, queryName 
FROM query_logs 
WHERE rcode = 'NXDOMAIN' 
ORDER BY timestamp DESC;
```

## Performance Considerations

**Disk I/O Impact**  
Each DNS query generates a database write operation. On high-traffic servers (>10,000 queries/second), consider using SSD storage for `logFolderPath` to minimize I/O latency.

**Database Locking**  
SQLite uses file-level locking. Concurrent write operations are serialized. In environments with multiple DNS worker threads, brief lock contention may occur. This is typically negligible for most deployments.

**Index Maintenance Overhead**  
The four defined indexes accelerate queries but increase write overhead by approximately 20-30%. This trade-off is acceptable for query-heavy analytical workloads.

**Memory Usage**  
SQLite maintains internal caches. For databases approaching 1GB, expect approximately 50-100MB of additional memory consumption per open database handle.

## Troubleshooting

### Logs Are Not Being Written

**Diagnostic Steps:**

1. Verify `enableLogging` is set to `true` in dnsApp.config

2. Check DNS Server application logs for SQLite-related error messages

3. Confirm `logFolderPath` directory exists and has write permissions for the DNS Server process user

4. Validate `dnsApp.config` is valid JSON using a parser

5. Restart the DNS Server application to reload configuration

**Common Resolution:**
```bash
mkdir -p /var/dns/query-logs
chown dnsserver:dnsserver /var/dns/query-logs
chmod 755 /var/dns/query-logs
```

### Database Files Are Not Rotating

**Diagnostic Steps:**

1. Verify `rotationInterval` is set to a valid value: `Hourly`, `Daily`, `Weekly`, or `Monthly`

2. Check system time and timezone settings if `useUtc` is `false`

3. Confirm `maxDatabaseSizeMB` has not been reached prematurely

4. Review application logs for rotation events

**Common Resolution:**

Manually trigger rotation by restarting the DNS Server at the expected rotation boundary, or reduce `maxDatabaseSizeMB` to force size-based rotation.

### Old Database Files Are Not Being Deleted

**Diagnostic Steps:**

1. Verify `maxLogFileDays` is configured correctly

2. Check file timestamps against current date/time

3. Confirm retention cleanup process is executing (check application logs)

4. Verify file system permissions allow deletion

**Common Resolution:**

The retention cleanup process runs periodically (typically every 6-24 hours). Manual cleanup can be performed:
```bash
find /var/dns/query-logs -name "queries_*.db" -mtime +90 -delete
```

### Database Corruption Errors

**Diagnostic Steps:**

1. Identify the corrupted database file from error logs

2. Attempt SQLite integrity check:
   ```bash
   sqlite3 /var/dns/query-logs/queries_2026-01-26.db "PRAGMA integrity_check;"
   ```

3. Check for disk space exhaustion

4. Review system logs for hardware errors or filesystem issues

**Common Resolution:**

Corrupted databases typically result from unclean shutdowns or hardware failures. If integrity check fails:
```bash
mv /var/dns/query-logs/queries_2026-01-26.db /var/dns/query-logs/queries_2026-01-26.db.corrupt
```

A new database will be created automatically. The corrupted file may be recoverable using SQLite recovery tools.

### High Disk Space Consumption

**Diagnostic Steps:**

1. Check total size of `logFolderPath`:
   ```bash
   du -sh /var/dns/query-logs
   ```

2. Verify `maxLogFileDays` retention policy is appropriate for available storage

3. Consider reducing retention period or increasing `rotationInterval` to reduce file count

4. Evaluate `maxDatabaseSizeMB` setting

**Common Resolution:**

Reduce retention period:
```json
{
  "maxLogFileDays": 30
}
```

Or implement external archival process to compress/move aged databases to secondary storage.

## Limitations

**No Built-In Query Interface**  
The application provides storage only. Analysis requires external SQLite tools or custom scripting.

**Single-Server Scope**  
Logs are stored locally. Multi-server deployments require aggregation mechanisms for centralized analysis.

**No Encryption at Rest**  
Database files are stored unencrypted. Implement filesystem-level encryption if regulatory requirements mandate encrypted storage.

**Limited Concurrency**  
SQLite's locking model may introduce brief serialization delays under extreme write loads (>50,000 queries/second).

## License

This application is part of the Technitium DNS Server project and is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

For complete license terms, see: https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE