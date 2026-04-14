# WildIp App

A DNS App for Technitium DNS Server that returns an IP address embedded in the queried name.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Subdomain parsing** – extracts IPv4 or IPv6 values from the query name
- **NODATA fallback** – returns an SOA-based NODATA response when parsing fails

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

Create an APP record for the base name you want to use (for example `ip.example.com`).

## Runtime behavior

### A queries

- Parses decimal octets from the subdomain using `.` and `-` separators.
- Example: `192-168-1-10.ip.example.com` → `192.168.1.10`

### AAAA queries

- Accepts either dashed IPv6 text converted to `:` or a 32-character hex string.
- If parsing succeeds, returns an AAAA record.
- If parsing fails, returns NODATA with the zone SOA in the authority section.

## Risks / operational notes

- Parsing is permissive and can match unintended labels.
- This is useful for testing, but be careful exposing it publicly.

## Troubleshooting

- Confirm the APP record name is correct.
- Confirm the subdomain format is valid for the target IP version.
