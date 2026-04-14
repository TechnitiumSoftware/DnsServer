# GeoContinent App

A DNS App for Technitium DNS Server that returns continent-specific answers based on the client's geolocation continent.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Continent mapping** – APP record JSON maps continent codes to response data
- **Default fallback** – optional `default` entry when no continent match exists

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

## Requirements

This app relies on the DNS server's geolocation database for continent lookup. Ensure the MaxMind GeoIP2/GeoLite2 database used by the server is installed and kept up to date.

If your deployment uses optional ISP/ASN geolocation data, keep that database updated as well.

## Installation

1. Open the Technitium DNS Server web console.
2. Install or update the app.
3. Make sure the geolocation database files are present and current.

### APP record JSON

```json
{
  "EU": { },
  "NA": { },
  "default": { }
}
```

> The important part is the continent-key mapping. The exact payload format is interpreted by the app/runtime.

## Runtime behavior

1. The app determines the client continent from geolocation.
2. It looks up the continent key in the APP record JSON.
3. If no match exists, it uses `default` when available.

## Risks / operational notes

- Geolocation can be inaccurate or unavailable for some clients.
- If `default` is missing, unmatched clients may receive no app-specific answer.

## Troubleshooting

- Verify the APP record contains valid JSON.
- Add a `default` entry if you need a fallback response.
- If lookups are missing or stale, update the GeoIP database files used by the DNS server.
