# Query Logs MySQL App

## Summary

A DNS App for Technitium DNS Server that logs DNS queries to a MySQL/MariaDB database with configurable retention.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsQueryLogger`, `IDnsQueryLogs`
- Runs as: a query logger (buffers and persists log entries asynchronously).

## Configuration

The app is configured using `dnsApp.config` (JSON).

### Root configuration options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `false` | Enables or disables query logging. |
| `maxQueueSize` | number | `1000000` | Maximum number of log entries allowed in the in-memory queue before new entries are dropped. |
| `maxLogDays` | number | `0` | Maximum age (days) to retain. `0` disables age-based cleanup. |
| `maxLogRecords` | number | `0` | Maximum number of records to retain. `0` disables count-based cleanup. |
| `databaseName` | string | `"DnsQueryLogs"` | Database name used to store logs. |
| `connectionString` | string | *(required)* | MySQL connection string **without** the database name. The app appends `Database={databaseName};` internally. |

### Example

```json
{
  "enableLogging": false,
  "maxQueueSize": 1000000,
  "maxLogDays": 0,
  "maxLogRecords": 0,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Server=192.168.180.128; Port=3306; Uid=username; Pwd=password;"
}