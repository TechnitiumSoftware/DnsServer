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

This app depends on the geolocation database to determine the client's continent.

A **MaxMind GeoIP2/GeoLite2 Country** database in `.mmdb` format must be installed. The app includes the GeoLite2 version for trial. For production usage, it is required that you purchase the GeoIP2 database from MaxMind (https://www.maxmind.com/).

- Required: a **GeoIP2/GeoLite2 Country** database file (`*.mmdb`)
- Optional: **GeoIP2/GeoLite2 ISP** and/or **GeoIP2/GeoLite2 ASN** database files (`*.mmdb`)

If the Country database is missing, this app cannot resolve the client continent and the app will throw errors instead of answering requests successfully.

### Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** section
3. Click **App Store** and find the Geo Continent App to install
4. Configure APP records in the appropriate DNS zone(s)

### Maxmind Database Update Procedure

1. Obtain a MaxMind **GeoIP2 Country** or **GeoLite2 Country** `.mmdb` database from MaxMind.
2. Zip the `.mmdb` file without renaming it.
3. Open the Technitium DNS Server web console
4. Navigate to **Apps** section
5. Find the Geo Continent app in the list of installed apps
6. Click on the **Update** button for the app and upload the zip file to complete the database update process.

Keep the database updated on a regular schedule by downloading the latest MaxMind release and updating it for the app.

### Optional ISP / ASN databases

The GeoContinent app only requires the **Country** database to map clients to continents. However, you may also install and maintain:

- **GeoIP2/GeoLite2 ISP**
- **GeoIP2/GeoLite2 ASN**

These optional databases are not required for continent-based responses in this app, but they are useful for the Autonomous System Number (ASN) based mapping feature and for selecting optimal EDNS Client Subnet scope prefix length value.

### APP record JSON

```json
{
  "EU": { },
  "NA": { },
  "AS1234": { },
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
