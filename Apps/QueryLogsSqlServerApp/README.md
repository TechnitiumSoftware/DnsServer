# Query Logs SQL Server App

A DNS App for Technitium DNS Server that logs DNS queries to a Microsoft SQL Server database.

## Overview

- **Async logging** – writes log entries through a bounded queue
- **Cleanup support** – prunes old records by age/count
- **Retained schema** – uses a database name and SQL Server connection string for storage

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsQueryLogger`, `IDnsQueryLogs`
- Runs as a DNS query logger with asynchronous persistence.

## Configuration

`dnsApp.config` contains these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `false` | Enables or disables query logging. |
| `maxQueueSize` | number | `1000000` | Maximum number of log entries allowed in the in-memory queue before new entries are dropped. |
| `maxLogDays` | number | `0` | Maximum age (days) to retain. `0` disables age-based cleanup. |
| `maxLogRecords` | number | `0` | Maximum number of records to retain. `0` disables count-based cleanup. |
| `databaseName` | string | `"DnsQueryLogs"` | Database name used to store logs. |
| `connectionString` | string | *(required)* | SQL Server connection string **without** selecting a database/initial catalog. The app uses `databaseName` separately. |

### Example

```json
{
  "enableLogging": false,
  "maxQueueSize": 1000000,
  "maxLogDays": 0,
  "maxLogRecords": 0,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Data Source=tcp:192.168.10.101,1433; User ID=username; Password=password; TrustServerCertificate=true;"
}
```

## Runtime behavior

1. Queries are buffered in a bounded channel.
2. A background consumer thread bulk inserts records into SQL Server storage.
3. A periodic cleanup timer removes old records.

## Risks / operational notes

- Queue overflow drops writes (`DropWrite` behavior).
- Database connectivity issues can stop logging.
- High traffic deployments should monitor write latency.

## Troubleshooting

- Confirm the database is reachable and credentials are valid.
- Check the connection string and `databaseName`.
- Review server logs for SQL client errors.
