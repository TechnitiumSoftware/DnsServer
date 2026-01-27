# Query Logs MySQL App

A DNS App for Technitium DNS Server that logs all incoming DNS queries and their responses to a MySQL or MariaDB database for persistent storage, advanced querying, and analysis through the DNS Server web console.

## Overview

The **Query Logs MySQL App** extends Technitium DNS Server's native logging capabilities by persisting DNS query logs to an external **MySQL** or **MariaDB** database. This enables long-term retention, scalable storage, and flexible query-based analysis beyond in-memory or local file-based logging.

**Core capabilities:**

- **Persistent logging** of DNS requests and responses to MySQL/MariaDB
- **Automatic schema creation and migration** on first run
- **Indexed database tables** for efficient query performance
- **Configurable retention policies** based on time (days) or record count
- **Bulk insert optimization** to minimize database transaction overhead
- **Asynchronous processing** using bounded channels to avoid DNS request blocking
- **Web console integration** for querying and filtering logs by timestamp, client IP, protocol, query type, response type, and RCODE

This app is suitable for **system administrators**, **ISPs**, **enterprises**, and **security operations teams** requiring centralized DNS query visibility and forensic analysis.

## ⚠️ Important Warning: Database Configuration

This app requires a properly configured MySQL or MariaDB database with correct user permissions. **Failure to configure the database correctly will prevent the app from functioning.**

### Option A: Create a dedicated database and user

1. Connect to MySQL/MariaDB as root or a privileged user
2. Execute the following commands:

```sql
CREATE USER 'dnsuser'@'%' IDENTIFIED BY 'strong_password';
CREATE DATABASE DnsQueryLogs;
GRANT ALL PRIVILEGES ON DnsQueryLogs.* TO 'dnsuser'@'%';
FLUSH PRIVILEGES;
```

3. Update the app's `dnsApp.config` with the connection string and credentials
4. Set `enableLogging` to `true` and save the configuration

### Option B: Use an existing user with database creation privileges

1. Ensure the user specified in `connectionString` has `CREATE DATABASE` and `CREATE TABLE` privileges
2. The app will automatically create the database specified in `databaseName` if it does not exist

**Critical considerations:**

- Do **not** include `Database=` in the `connectionString` parameter—use the separate `databaseName` parameter instead
- The app will fail to start if connection credentials are invalid or database permissions are insufficient
- On startup, the app retries connection up to 20 times (30-second intervals) before giving up
- Check the DNS Server logs for MySQL connection errors if the app fails to initialize

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** in the main menu
3. Click **Install App** or **Update App** if already installed
4. Upload or select the **QueryLogsMySqlApp** package
5. Click **Install** and wait for confirmation
6. Navigate to the app's **Config** section to configure database settings

## Configuration

The app is configured using the `dnsApp.config` JSON file. The file controls database connection, logging behavior, and retention policies.

Configuration is applied immediately upon saving changes through the web console. Schema creation and index generation occur automatically on first initialization.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | Boolean | `false` | Enables or disables DNS query logging. Set to `true` to activate logging. |
| `maxQueueSize` | Integer | `1000000` | Maximum number of log entries allowed in the in-memory queue before new entries are dropped. |
| `maxLogDays` | Integer | `0` | Maximum age (in days) for log retention. Logs older than this are deleted. `0` disables time-based cleanup. |
| `maxLogRecords` | Integer | `0` | Maximum number of log records to retain in the database. Oldest records are deleted when the limit is exceeded. `0` disables count-based cleanup. |
| `databaseName` | String | `"DnsQueryLogs"` | Name of the MySQL/MariaDB database to use for storing logs. Created automatically if it does not exist. |
| `connectionString` | String | `null` | MySQL connection string without the `Database=` parameter. Must include `Server`, `Port`, `Uid`, and `Pwd`. |

### Database Schema

The app automatically creates the `dns_logs` table with the following structure:

| Column | Type | Description |
|--------|------|-------------|
| `dlid` | `INT AUTO_INCREMENT PRIMARY KEY` | Unique log entry identifier |
| `server` | `VARCHAR(255)` | DNS server domain name |
| `timestamp` | `DATETIME` | UTC timestamp of the query |
| `client_ip` | `VARCHAR(39)` | Client IP address (IPv4 or IPv6) |
| `protocol` | `TINYINT UNSIGNED` | Transport protocol: `1` = UDP, `2` = TCP, `3` = TLS, `4` = HTTPS, `5` = QUIC |
| `response_type` | `TINYINT` | DNS server response type (e.g., Recursive, Authoritative, Cached, Blocked) |
| `response_rtt` | `REAL` | Round-trip time in milliseconds for recursive queries |
| `rcode` | `TINYINT` | DNS response code (e.g., `0` = NoError, `3` = NXDomain) |
| `qname` | `VARCHAR(255)` | Queried domain name (lowercase) |
| `qtype` | `SMALLINT` | DNS query type (e.g., `1` = A, `28` = AAAA, `5` = CNAME) |
| `qclass` | `SMALLINT` | DNS query class (typically `1` = IN for Internet) |
| `answer` | `VARCHAR(4000)` | Serialized DNS answer records or `[ZONE TRANSFER]` for AXFR/IXFR |

**Indexes created automatically:**

- `index_server` on `server`
- `index_timestamp` on `timestamp`
- `index_client_ip` on `client_ip`
- `index_protocol` on `protocol`
- `index_response_type` on `response_type`
- `index_rcode` on `rcode`
- `index_qname` on `qname`
- `index_qtype` on `qtype`
- `index_qclass` on `qclass`
- `index_timestamp_client_ip` on `(timestamp, client_ip)`
- `index_timestamp_qname` on `(timestamp, qname)`
- `index_client_qname` on `(client_ip, qname)`
- `index_query` on `(qname, qtype)`
- `index_all` on all filterable columns

## Example Configuration

```json
{
  "enableLogging": true,
  "maxQueueSize": 1000000,
  "maxLogDays": 30,
  "maxLogRecords": 10000000,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Server=192.168.1.100; Port=3306; Uid=dnsuser; Pwd=SecurePassword123;"
}
```

**Explanation:**

- Logging is **enabled**
- In-memory queue holds up to **1 million** entries before dropping new logs
- Logs older than **30 days** are automatically deleted
- Database retains up to **10 million** records (oldest records deleted when exceeded)
- MySQL server located at `192.168.1.100`, port `3306`
- Database named `DnsQueryLogs`
- Authenticated with user `dnsuser` and password `SecurePassword123`

## How It Works

The Query Logs MySQL App processes DNS queries using an asynchronous pipeline to minimize performance impact on DNS resolution:

1. **Capture**: Each DNS request and response is captured via the `IDnsQueryLogger` interface after the DNS server processes the query.

2. **Queue**: Log entries are written to a bounded in-memory channel configured with `maxQueueSize`. If the queue is full, new log entries are dropped (using `BoundedChannelFullMode.DropWrite`).

3. **Batch**: A dedicated consumer thread continuously reads from the channel and accumulates up to **1,000 log entries** into a batch.

4. **Insert**: The batch is inserted into the MySQL database using a single bulk `INSERT` statement with parameterized values to prevent SQL injection.

5. **Cleanup**: A periodic timer runs every **15 minutes** to enforce retention policies:
   - Deletes records older than `maxLogDays` (if configured)
   - Deletes oldest records exceeding `maxLogRecords` (if configured)

6. **Retry Logic**: On startup, the app retries database connections up to **20 times** (30-second intervals) to handle temporary network or database unavailability.

## Use Cases

**DNS query auditing for compliance**  
Organizations subject to regulatory compliance (e.g., GDPR, HIPAA, PCI-DSS) can log all DNS queries for audit trails and forensic investigations.

**Security threat detection**  
Security teams can query the database to detect DNS tunneling, domain generation algorithms (DGA), or exfiltration attempts by analyzing query patterns.

**Network troubleshooting**  
System administrators can identify misconfigured clients, recursive resolution failures, or latency issues by filtering logs by client IP, response code, or round-trip time.

**Traffic analysis and capacity planning**  
ISPs and enterprises can analyze query volume, protocol distribution, and geographic patterns to optimize DNS infrastructure and plan for growth.

**Malware detection and response**  
Incident responders can correlate DNS queries to known malicious domains or C2 infrastructure by querying historical logs.

**Internal DNS monitoring**  
Organizations can monitor internal DNS usage to enforce acceptable use policies, detect shadow IT, or identify misconfigured applications.

## Troubleshooting

### Logging is enabled but no records appear in the database

**Diagnosis:**

1. Check DNS Server logs for MySQL connection errors:
   - Navigate to **Logs** in the web console
   - Look for `MySqlException` or connection timeout messages

2. Verify database credentials and connectivity:

```bash
mysql -h 192.168.1.100 -P 3306 -u dnsuser -p
```

3. Confirm the database and table exist:

```sql
USE DnsQueryLogs;
SHOW TABLES;
DESCRIBE dns_logs;
```

4. Check the in-memory queue status by reviewing app initialization logs. If `maxQueueSize` is too small, logs may be dropped.

**Resolution:**

- Correct connection string, username, or password in `dnsApp.config`
- Ensure MySQL/MariaDB is running and accessible from the DNS server
- Grant required privileges to the database user
- Increase `maxQueueSize` if logs are being dropped

### Database connection fails on startup

**Diagnosis:**

1. Review DNS Server logs for error codes:
   - `UnableToConnectToHost`: Network or firewall issue
   - `TooManyUserConnections`: MySQL `max_connections` limit reached
   - `AccessDenied`: Invalid credentials or insufficient privileges

2. Test network connectivity:

```bash
telnet 192.168.1.100 3306
```

3. Verify MySQL user privileges:

```sql
SHOW GRANTS FOR 'dnsuser'@'%';
```

**Resolution:**

- Configure firewall to allow port `3306` (MySQL)
- Increase MySQL `max_connections` in `my.cnf` or `my.ini`
- Recreate user with correct privileges:

```sql
DROP USER 'dnsuser'@'%';
CREATE USER 'dnsuser'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON DnsQueryLogs.* TO 'dnsuser'@'%';
```

### Logs are not deleted despite retention settings

**Diagnosis:**

1. Verify `maxLogDays` or `maxLogRecords` is set to a value greater than `0`
2. Check DNS Server logs for cleanup timer exceptions
3. Confirm the cleanup timer is running (executes every 15 minutes after the first 5 seconds)

**Resolution:**

- Save the configuration to trigger timer reinitialization
- Manually delete old records:

```sql
DELETE FROM dns_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

### Bulk insert errors or delays

**Diagnosis:**

1. Check DNS Server logs for `MySqlException` during bulk insert operations
2. Review MySQL slow query log for long-running `INSERT` statements
3. Monitor database server CPU and I/O utilization

**Resolution:**

- Increase MySQL `max_allowed_packet` size in `my.cnf`
- Optimize MySQL buffer pool size (`innodb_buffer_pool_size`)
- Reduce `BULK_INSERT_COUNT` by modifying the app source and recompiling
- Use faster storage (SSD) for the MySQL data directory

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

Copyright (C) 2025 Shreyas Zare (shreyas@technitium.com)

You are free to redistribute and modify this software under the terms of the GPL-3.0 license. See [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/) for full license text.