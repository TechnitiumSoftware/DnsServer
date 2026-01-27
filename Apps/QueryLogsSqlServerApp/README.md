# Query Logs SQL Server App

A DNS App for Technitium DNS Server that logs all incoming DNS requests and their responses in a Microsoft SQL Server database for centralized query log management and analysis.

## Overview

The Query Logs SQL Server App extends Technitium DNS Server's logging capabilities by storing DNS query data in a Microsoft SQL Server database. This enables:

- **Centralized logging** for distributed DNS server deployments
- **Advanced query capabilities** with SQL-based filtering and analysis
- **Long-term retention** of DNS query logs with configurable retention policies
- **Enterprise integration** with existing SQL Server infrastructure
- **High-performance bulk insertion** using optimized batch processing

This app is designed for administrators requiring enterprise-grade DNS query logging with robust filtering, searching, and reporting capabilities through the DNS Server web console.

## Installation

1. Open the Technitium DNS Server web console

2. Navigate to **Apps** in the administration panel

3. Click **Install/Update App** and select the Query Logs SQL Server App package

4. Configure the app using the `dnsApp.config` file or web console interface

## Configuration

Configuration is defined in the `dnsApp.config` JSON file located in the app directory.

All configuration changes require app reinitialization to take effect.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `false` | Enables or disables DNS query logging to SQL Server |
| `maxQueueSize` | integer | `1000000` | Maximum number of log entries buffered in memory before writes are blocked |
| `maxLogDays` | integer | `0` | Maximum age in days for log retention; `0` disables age-based cleanup |
| `maxLogRecords` | integer | `0` | Maximum number of log records to retain; `0` disables count-based cleanup |
| `databaseName` | string | `"DnsQueryLogs"` | Name of the SQL Server database to create or use for storing logs |
| `connectionString` | string | (required) | SQL Server connection string without `Initial Catalog` parameter |

### Connection String Configuration

The `connectionString` parameter must **not** include the `Initial Catalog` parameter, as the database name is specified separately via `databaseName`.

**Required format:**

```json
"connectionString": "Data Source=tcp:<server>,<port>; User ID=<username>; Password=<password>; TrustServerCertificate=true;"
```

**Important considerations:**

- Connection string must end with a semicolon (`;`) or one will be appended automatically
- Database is automatically created if it does not exist
- User credentials must have permissions to create databases, tables, and indexes
- The app automatically creates the `dns_logs` table and associated indexes on first initialization

### Queue and Performance Configuration

The app uses a **bounded channel** with configurable queue size (`maxQueueSize`) to buffer log entries for bulk insertion. Bulk inserts process up to **190 entries per batch** to remain within SQL Server's 2,100 parameter limit.

**Channel behavior:**
- Single writer, single reader pattern for optimal performance
- `DropWrite` mode when queue is full (new entries are silently discarded)
- Background consumer thread performs asynchronous bulk insertions

**Queue sizing guidance:**
- Default: 1,000,000 entries
- High-traffic environments: Consider increasing to 5,000,000 or more
- Monitor queue drops via DNS server logs

### Retention Policy Configuration

Two independent retention policies can be configured:

| Policy | Parameter | Behavior |
|--------|-----------|----------|
| Age-based | `maxLogDays` | Deletes records older than specified days |
| Count-based | `maxLogRecords` | Deletes oldest records when count is exceeded |

**Cleanup execution:**

- Initial cleanup runs 5 seconds after app initialization
- Periodic cleanup runs every 15 minutes thereafter
- Both policies are applied independently if configured
- Set both to `0` to disable automatic cleanup

## Database Schema

### `dns_logs` Table

The app automatically creates the following table structure:

| Column | Type | Description |
|--------|------|-------------|
| `dlid` | INT IDENTITY(1,1) PRIMARY KEY | Auto-incrementing log entry ID |
| `server` | VARCHAR(255) | DNS server domain name |
| `timestamp` | DATETIME | Query timestamp (UTC) |
| `client_ip` | VARCHAR(39) | Client IP address (IPv4 or IPv6) |
| `protocol` | TINYINT | Transport protocol (UDP=1, TCP=2, etc.) |
| `response_type` | TINYINT | Response type (Recursive, Authoritative, Cached, etc.) |
| `response_rtt` | REAL | Response round-trip time in milliseconds (nullable) |
| `rcode` | TINYINT | DNS response code (NoError=0, NXDomain=3, etc.) |
| `qname` | VARCHAR(255) | Queried domain name (lowercase) |
| `qtype` | SMALLINT | DNS query type (A=1, AAAA=28, etc.) |
| `qclass` | SMALLINT | DNS query class (IN=1, etc.) |
| `answer` | VARCHAR(4000) | Answer records formatted as "TYPE RDATA" pairs |

### Indexes

The following indexes are automatically created for optimal query performance:

- `index_server` on `server`
- `index_timestamp` on `timestamp`
- `index_client_ip` on `client_ip`
- `index_protocol` on `protocol`
- `index_response_type` on `response_type`
- `index_rcode` on `rcode`
- `index_qname` on `qname`
- `index_qtype` on `qtype`
- `index_qclass` on `qclass`
- `index_timestamp_client_ip` on `timestamp, client_ip`
- `index_timestamp_qname` on `timestamp, qname`
- `index_client_qname` on `client_ip, qname`
- `index_query` on `qname, qtype`
- `index_all` on `server, timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass`

## Example Configuration

### Basic Configuration

```json
{
  "enableLogging": true,
  "maxQueueSize": 1000000,
  "maxLogDays": 0,
  "maxLogRecords": 0,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Data Source=tcp:192.168.10.101,1433; User ID=username; Password=password; TrustServerCertificate=true;"
}
```

### Configuration with Retention Policies

```json
{
  "enableLogging": true,
  "maxQueueSize": 5000000,
  "maxLogDays": 30,
  "maxLogRecords": 10000000,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Data Source=tcp:sql-server.example.com,1433; User ID=dns_logger; Password=SecurePassword123; TrustServerCertificate=true;"
}
```

This configuration:
- Enables logging with a 5 million entry queue
- Retains logs for maximum 30 days
- Limits total records to 10 million entries
- Uses a custom database name and remote SQL Server

## How It Works

The Query Logs SQL Server App processes DNS queries through the following pipeline:

1. **Query Interception**: DNS Server invokes `InsertLogAsync()` for each completed DNS query when logging is enabled

2. **Queue Buffering**: Log entries are written to a bounded in-memory channel with configurable capacity

3. **Batch Accumulation**: Background consumer thread reads up to 190 entries from the queue to form a bulk insert batch

4. **Bulk Insertion**: Batched entries are inserted using parameterized SQL INSERT statements with optimized parameter binding

5. **Error Handling**: Failed insertions trigger a 10-second delay before retry; errors are logged to DNS Server logs

6. **Automatic Cleanup**: Periodic timer executes retention policies by deleting records exceeding age or count limits

7. **Query Processing**: Web console queries are translated to parameterized SQL SELECT statements with pagination and filtering

## Supported Query Filters

When querying logs via the DNS Server web console, the following filters are supported:

| Filter | SQL Column | Format | Wildcard Support |
| --- | --- | --- | --- |
| Server | `server` | String | No |
| Start Time | `timestamp >= @start` | DateTime | No |
| End Time | `timestamp <= @end` | DateTime | No |
| Client IP | `client_ip` | IPv4/IPv6 | No |
| Protocol | `protocol` | Enum (UDP/TCP/etc.) | No |
| Response Type | `response_type` | Enum | No |
| Response Code | `rcode` | Enum (NoError/NXDomain/etc.) | No |
| Query Name | `qname` | Domain name (lowercase) | Yes (`*` as wildcard) |
| Query Type | `qtype` | Enum (A/AAAA/MX/etc.) | No |
| Query Class | `qclass` | Enum (IN/etc.) | No |

**Wildcard query name examples:**
- `*.example.com` matches `mail.example.com`, `www.example.com`, etc.
- `example.*` matches `example.com`, `example.net`, etc.

## Answer Field Format

The `answer` column stores DNS response data in the following formats:

| Scenario | Format |
|----------|--------|
| No answer | `NULL` |
| Single record | `<TYPE> <RDATA>` |
| Multiple records | `<TYPE1> <RDATA1>, <TYPE2> <RDATA2>, ...` |
| Zone transfer | `[ZONE TRANSFER]` |
| Truncated (>4000 chars) | First 4000 characters |

**Examples:**
- `A 192.168.1.1`
- `AAAA 2001:db8::1, AAAA 2001:db8::2`
- `CNAME www.example.com, A 203.0.113.1`

## Use Cases

### Centralized Logging for DNS Infrastructure

Deploy Query Logs SQL Server App across multiple DNS server instances to aggregate all DNS query data into a centralized SQL Server database for unified reporting and analysis.

### Security Monitoring and Threat Detection

Query the `dns_logs` table to identify suspicious DNS patterns such as:
- High query volumes from single clients
- Queries for known malicious domains
- Unusual query types (e.g., DNS tunneling patterns)
- NXDOMAIN abuse indicating DGA activity

### Compliance and Audit Requirements

Maintain tamper-evident DNS query logs in SQL Server with automated retention policies to meet regulatory compliance requirements for data retention and auditability.

### Network Troubleshooting and Performance Analysis

Analyze DNS query patterns, response times, and error rates to identify:
- Clients with DNS configuration issues
- Slow or failing upstream resolvers
- Traffic patterns for capacity planning
- Protocol distribution (UDP vs TCP vs DoH/DoT)

### Business Intelligence and Reporting

Leverage SQL Server's reporting capabilities (SSRS, Power BI, etc.) to generate custom DNS analytics dashboards and reports for operational insights.

### Forensic Investigation

Perform historical DNS query analysis during security incidents to reconstruct attacker activity timelines and identify compromised systems based on DNS query patterns.

## Troubleshooting

### App Fails to Initialize with Connection Errors

**Symptoms**: DNS Server logs show SQL connection failures with error code 258 or other connection-related errors.

**Diagnostic steps:**

1. Verify SQL Server is running and accessible from the DNS Server host:

   ```bash
   telnet <sql-server> 1433
   ```

2. Check the connection string for correct hostname, port, username, and password

3. Verify firewall rules allow TCP connections to SQL Server port (default 1433)

4. Check SQL Server authentication mode (must support SQL Server authentication if using username/password)

**Resolution:**

- For error code 258 (timeout): App retries up to 20 times with 30-second delays on startup
- For other errors: Correct connection string and restart the app
- Check DNS Server logs for detailed error messages

### Logs Are Not Being Written to Database

**Symptoms**: `dns_logs` table remains empty despite `enableLogging: true`.

**Diagnostic steps:**

1. Verify `enableLogging` is set to `true` in `dnsApp.config`

2. Check DNS Server logs for bulk insert errors

3. Verify database and table exist:

   ```sql
   USE DnsQueryLogs;
   SELECT COUNT(*) FROM dns_logs;
   ```

4. Monitor queue drops by checking channel statistics (if queue is full, entries are silently discarded)

**Resolution:**

- Increase `maxQueueSize` if queries are being dropped due to high traffic
- Verify SQL Server has sufficient disk space and resources
- Check SQL Server permissions for the configured user account

### Query Performance Is Slow

**Symptoms**: Web console log queries take excessive time to return results.

**Diagnostic steps:**

1. Check index usage with SQL Server execution plans

2. Verify indexes exist on `dns_logs` table:

   ```sql
   USE DnsQueryLogs;
   EXEC sp_helpindex 'dns_logs';
   ```

3. Check table size:

   ```sql
   SELECT COUNT(*) FROM dns_logs;
   ```

**Resolution:**

- Enable retention policies (`maxLogDays` or `maxLogRecords`) to limit table growth
- Consider partitioning the `dns_logs` table for large datasets (>100M records)
- Optimize queries to use indexed columns (timestamp, client_ip, qname, etc.)

### Database Grows Too Large

**Symptoms**: SQL Server database consumes excessive disk space.

**Diagnostic steps:**

1. Check current record count:

   ```sql
   SELECT COUNT(*) FROM dns_logs;
   ```

2. Review retention policy configuration in `dnsApp.config`

**Resolution:**

- Configure `maxLogDays` to automatically delete old records (e.g., `30` for 30-day retention)
- Configure `maxLogRecords` to limit total record count (e.g., `10000000` for 10M records)
- Manually delete old records if needed:

   ```sql
   DELETE FROM dns_logs WHERE timestamp < '2025-01-01';
   ```

- Enable SQL Server database compression for the `dns_logs` table

### Bulk Insert Errors in DNS Server Logs

**Symptoms**: DNS Server logs show repeated errors during bulk insert operations.

**Diagnostic steps:**

1. Review error messages in DNS Server logs for SQL error codes

2. Verify SQL Server connection stability

3. Check for parameter limit violations (should not occur with BULK_INSERT_COUNT=190)

**Resolution:**

- App automatically retries after 10-second delay on bulk insert failures
- Verify network stability between DNS Server and SQL Server
- Check SQL Server resource availability (CPU, memory, disk I/O)
- Review SQL Server error logs for detailed failure reasons

## License

This application is part of Technitium DNS Server.

Copyright (C) 2025 Shreyas Zare (shreyas@technitium.com)

Licensed under GNU General Public License v3.0. See [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html) for details.