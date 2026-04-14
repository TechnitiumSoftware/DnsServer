# Query Logs SQLite App

A DNS App for Technitium DNS Server that logs DNS queries to a SQLite database.

## Overview

- **Async logging** – writes log entries through a bounded queue
- **Cleanup support** – prunes old records by age/count
- **Optional in-memory mode** – can use an in-memory database
- **Vacuum support** – can vacuum after cleanup when enabled

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsQueryLogger`, `IDnsQueryLogs`
- Runs as a DNS query logger with asynchronous persistence.

## Configuration

`dnsApp.config` contains these keys:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `true` | Enables or disables logging. |
| `maxQueueSize` | number | `200000` | Size of the bounded log queue. |
| `maxLogDays` | number | `0` | Maximum age of retained logs (days). `0` disables age-based cleanup. |
| `maxLogRecords` | number | `0` | Maximum number of retained log records. `0` disables count-based cleanup. |
| `enableVacuum` | boolean | `false` | Runs `VACUUM` after cleanup when records were deleted. |
| `useInMemoryDb` | boolean | `false` | Uses an in-memory SQLite database. |
| `sqliteDbPath` | string | `querylogs.db` | Path to the SQLite database file. |
| `connectionString` | string | `Data Source='{sqliteDbPath}'; Cache=Shared;` | SQLite connection string template. |

The example below matches the shipped `dnsApp.config` values, which enable 7-day and 10,000-record cleanup by default in the distributed package.

### Example

```json
{
  "enableLogging": true,
  "maxQueueSize": 200000,
  "maxLogDays": 7,
  "maxLogRecords": 10000,
  "enableVacuum": false,
  "useInMemoryDb": false,
  "sqliteDbPath": "querylogs.db",
  "connectionString": "Data Source='{sqliteDbPath}'; Cache=Shared;"
}
```

## Runtime behavior

1. Queries are buffered in a bounded channel.
2. A background consumer thread bulk inserts records into SQLite.
3. A periodic cleanup timer removes old records.
4. If `enableVacuum` is enabled and cleanup deleted records, the database is vacuumed.

## Risks / operational notes

- Queue overflow drops writes (`DropWrite` behavior).
- SQLite write contention can affect high traffic deployments.
- In-memory mode does not persist across restarts.

## Troubleshooting

- Confirm the database path is writable.
- Confirm `connectionString` still contains the `{sqliteDbPath}` token.
- Check server logs for SQLite errors if logging stops.