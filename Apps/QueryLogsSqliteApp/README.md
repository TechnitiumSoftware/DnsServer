# Query Logs SQLite App

## Summary

A DNS App for Technitium DNS Server that logs DNS queries to a SQLite database with configurable retention.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsQueryLogger`, `IDnsQueryLogs`
- Runs as: a query logger (buffers and persists log entries asynchronously).

## Configuration

The app is configured using `dnsApp.config` (JSON).

### Root configuration options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `true` | Master switch to enable/disable query logging. |
| `maxQueueSize` | number | `200000` | Maximum number of queued log entries waiting to be written to SQLite. |
| `maxLogDays` | number | `7` | Maximum age (in days) of log data to keep. Older entries are deleted during cleanup. |
| `maxLogRecords` | number | `10000` | Maximum number of log records to keep (used by cleanup logic). |
| `enableVacuum` | boolean | `false` | When `true`, run SQLite `VACUUM` as part of maintenance (can be expensive for large databases). |
| `useInMemoryDb` | boolean | `false` | When `true`, use an in-memory SQLite database (logs are not persisted across restarts unless copied elsewhere by the app). |
| `sqliteDbPath` | string | `querylogs.db` | Path to the SQLite database file when `useInMemoryDb` is `false`. |
| `connectionString` | string | `Data Source='{sqliteDbPath}'; Cache=Shared;` | SQLite connection string template. The `{sqliteDbPath}` token is replaced with the configured database path. |

## Example

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