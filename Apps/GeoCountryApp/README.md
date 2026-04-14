# GeoCountry App

A DNS App for Technitium DNS Server that returns country-specific answers based on the client's geolocation country.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Country mapping** – APP record JSON maps country codes to response data
- **Default fallback** – optional `default` entry when no country match exists

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

## Requirements

This app depends on the DNS server's geolocation support to determine the client's country.

A **MaxMind GeoIP2/GeoLite2 Country** database in `.mmdb` format must be installed and configured for the server.

- Required: a **GeoIP2/GeoLite2 Country** database file (`*.mmdb`)
- Optional: **GeoIP2/GeoLite2 ISP** and/or **GeoIP2/GeoLite2 ASN** database files (`*.mmdb`) if you also use those lookups elsewhere

If the Country database is missing, this app cannot resolve the client country and the app will throw instead of answering requests successfully.

### Installation / update procedure

1. Obtain a MaxMind **GeoIP2 Country** or **GeoLite2 Country** `.mmdb` database from MaxMind.
2. Install the `.mmdb` file in the location used by Technitium DNS Server for GeoIP databases, or configure the server to use that file according to the server's GeoIP/geolocation settings.
3. Restart the DNS service or reload GeoIP/geolocation settings if required by your deployment so the updated database is picked up.
4. Verify geolocation is working before relying on this app in production.

Keep the database updated on a regular schedule by downloading the latest MaxMind release and replacing the existing `.mmdb` file using the same location/configuration.

### Optional ISP / ASN databases

The GeoCountry app only requires the **Country** database to map clients to countries. However, you may also install and maintain:

- **GeoIP2/GeoLite2 ISP**
- **GeoIP2/GeoLite2 ASN**

These optional databases are not required for country-based responses in this app, but they may be useful for other DNS server features or apps that use ISP/ASN metadata.

### APP record JSON

The APP record payload is a JSON object keyed by country code, with an optional `default` entry.

```json
{
  "US": { },
  "DE": { },
  "default": { }
}
```

> The exact per-country payload is interpreted by the app/runtime. The important part is the country-key mapping.

## Runtime behavior

1. The app determines the client country from geolocation.
2. It looks up the matching country key in the APP record JSON.
3. If no match exists, it uses `default` when available.

## Risks / operational notes

- Geolocation is not perfect; some IPs may resolve to the wrong country.
- If `default` is not provided, unmatched clients may receive no app-specific answer.

## Troubleshooting

- Verify the APP record contains valid JSON.
- Add a `default` entry for clients whose country cannot be determined.
- If lookups are missing or stale, update the GeoIP database files used by the DNS server.
