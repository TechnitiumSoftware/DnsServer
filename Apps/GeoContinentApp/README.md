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

## MaxMind database requirement

This app depends on the DNS server's geolocation support to determine the client's continent.

A **MaxMind GeoIP2/GeoLite2 Country** database in `.mmdb` format must be installed and configured for the server.

- Required: a **GeoIP2/GeoLite2 Country** database file (`*.mmdb`)
- Optional: **GeoIP2/GeoLite2 ISP** and/or **GeoIP2/GeoLite2 ASN** database files (`*.mmdb`) if you also use those lookups elsewhere

If the Country database is missing, this app cannot resolve the client continent and the app will throw instead of answering requests successfully.

### Installation / update procedure

1. Obtain a MaxMind **GeoIP2 Country** or **GeoLite2 Country** `.mmdb` database from MaxMind.
2. Install the `.mmdb` file in the location used by Technitium DNS Server for GeoIP databases, or configure the server to use that file according to the server's GeoIP/geolocation settings.
3. Restart the DNS service or reload GeoIP/geolocation settings if required by your deployment so the updated database is picked up.
4. Verify geolocation is working before relying on this app in production.

Keep the database updated on a regular schedule by downloading the latest MaxMind release and replacing the existing `.mmdb` file using the same location/configuration.

### Optional ISP / ASN databases

The GeoContinent app only requires the **Country** database to map clients to continents. However, you may also install and maintain:

- **GeoIP2/GeoLite2 ISP**
- **GeoIP2/GeoLite2 ASN**

These optional databases are not required for continent-based responses in this app, but they may be useful for other DNS server features or apps that use ISP/ASN metadata.

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
