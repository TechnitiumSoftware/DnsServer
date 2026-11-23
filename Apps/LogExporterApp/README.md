# Log Exporter App

Exports DNS query log entries, including optional structured blocking provenance, to File, HTTP, and Syslog targets.

## Configuration

The app is configured using `dnsApp.config` (JSON).

- `enableEdnsLogging`: Include the EDNS extended-error information when available. This is independent of structured blocking metadata.

When the DNS server's node-local `logQueryMetadata` option is enabled, the extended query logger receives `blockingMetadata` for built-in blocked-zone and block-list decisions. File and HTTP JSON output includes `blockingMetadata`; Syslog uses `blocking_` properties. When the option is off, the field is omitted. Other blocking DNS Apps require separate producer support.

This LogExporter build requires a DNS server release containing `IDnsQueryLoggerEx`. App Store minimum-version metadata should be updated when the server change is released.

See the shipped `dnsApp.config` for the remaining export target settings.
