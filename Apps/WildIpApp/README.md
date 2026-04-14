# WildIp App

## Summary

A DNS App for Technitium DNS Server that returns an IP address embedded in the queried name (similar to `sslip.io`).

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as: an APP-record request handler (answers are provided from the APP record context).

## Configuration

This app is **APP-record driven**.

- `dnsApp.config` is not used by this app.
- Create an **APP record** for a base name (for example, `ip.example.com`).
- The APP record data is not used; configuration is implicit.

## Runtime behavior

### A queries (IPv4)

The app parses decimal octets from the subdomain labels (from the left, before the APP record name) using `.` and `-` as separators.

Example: Query `192-168-1-10.ip.example.com` (type `A`) → Response `192.168.1.10`

### AAAA queries (IPv6)

The app looks for either:

- A label containing `-` which is converted to `:` and parsed as an IPv6 address, or
- A 32-hex-character label which is split into hextets and parsed.

If parsing fails, the app returns NOERROR with an SOA record (NODATA).

## Risks / operational notes

- **Ambiguous parsing**: multiple formats and separators can cause unexpected matches; test patterns thoroughly.
- **Unintended matches**: can accidentally answer for names you didn't intend; use specific APP record names.
- **Potential for abuse**: can be used for scanning/reconnaissance; consider network ACLs if exposed publicly.
