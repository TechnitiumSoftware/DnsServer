Here is a shortened README matching the style and scope of the MISP-connector example.

---

# Log Exporter for Technitium DNS Server

A plugin that exports DNS query logs to external sinks such as files, HTTP endpoints and Syslog servers. It is great for connecting to SIEM or similar products.

It maintains an in-memory queue with periodic bulk flushing and supports enriched EDNS logging.

## Features

* Captures DNS queries and responses using the Technitium DNS `IDnsQueryLogger` interface.
* Queues log entries asynchronously and flushes them in batches every 10 seconds.
* Exports logs via pluggable strategies: file output, HTTP POST and Syslog (UDP, TCP, TLS or local).
* Includes question, answer, RTT, response code and optional EDNS Extended DNS Error data.
* Limits memory usage with a configurable maximum queue size.
* Flushes all pending logs on shutdown.

## Configuration

Provide JSON configuration similar to:

```json
{
  "maxQueueSize": 50000,
  "enableEdnsLogging": true,
  "file": {
    "enabled": false,
    "path": "/var/log/technitium/dns.log"
  },
  "http": {
    "enabled": true,
    "endpoint": "https://collector.example.com/dns",
    "headers": { "Authorization": "Bearer token" }
  },
  "syslog": {
    "enabled": false,
    "address": "10.0.0.5",
    "port": 6514,
    "protocol": "tls"
  }
}
```

* Enable or disable each export target independently.
* Use `enableEdnsLogging` to include EDNS Extended DNS Error records.
* `maxQueueSize` prevents the queue from growing unbounded.

## Acknowledgement

Thanks to the Technitium DNS Server project for providing the application and logging interfaces.
