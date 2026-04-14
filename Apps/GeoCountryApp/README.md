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

This app relies on the DNS server's geolocation database for country lookup. Ensure the MaxMind GeoIP2/GeoLite2 Country database is installed and kept up to date.

If your deployment uses optional ISP/ASN geolocation data, keep that database updated as well.

## Installation

1. Open the Technitium DNS Server web console.
2. Install or update the app.
3. Make sure the geolocation database files are present and current.

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
