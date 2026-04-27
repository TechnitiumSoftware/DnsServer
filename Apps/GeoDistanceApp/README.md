# GeoDistance App

A DNS App for Technitium DNS Server that serves answers based on geographic distance.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Distance-based selection** – chooses responses using location data in the APP record payload
- **Per-zone flexibility** – different zones can define different distance mappings

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

## MaxMind database requirement

This app depends on the geolocation database to determine the client's geo distance from the servers.

A **MaxMind GeoIP2/GeoLite2 City** database in `.mmdb` format must be installed. The app includes the GeoLite2 version for trial. For production usage, it is required that you purchase the GeoIP2 database from MaxMind (https://www.maxmind.com/).

- Required: a **GeoIP2/GeoLite2 City** database file (`*.mmdb`)
- Optional: **GeoIP2/GeoLite2 ISP** and/or **GeoIP2/GeoLite2 ASN** database files (`*.mmdb`)

If the City database is missing, this app cannot resolve the client's geo distance and the app will throw errors instead of answering requests successfully.

WARNING: Latitude and longitude are not precise and should not be used to identify a particular street address or household.

### Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** section
3. Click **App Store** and find the Geo Distance App to install
4. Configure APP records in the appropriate DNS zone(s)

### Maxmind Database Update Procedure

1. Obtain a MaxMind **GeoIP2 City** or **GeoLite2 City** `.mmdb` database from MaxMind.
2. Zip the `.mmdb` file without renaming it.
3. Open the Technitium DNS Server web console
4. Navigate to **Apps** section
5. Find the Geo Distance app in the list of installed apps
6. Click on the **Update** button for the app and upload the zip file to complete the database update process.

Keep the database updated on a regular schedule by downloading the latest MaxMind release and updating it for the app.

### Optional ISP / ASN databases

The Geo Distance app only requires the **City** database to find client's geo distance. However, you may also install and maintain:

- **GeoIP2/GeoLite2 ISP**
- **GeoIP2/GeoLite2 ASN**

These optional databases are not required for distance-based responses in this app, but they are useful for selecting optimal EDNS Client Subnet scope prefix length value.

### APP record data

The app consumes APP record JSON that defines targets/coordinates/addresses. The exact schema is interpreted by the app/runtime; the key point is that the configuration is stored in the APP record payload, not in root app settings.

## Runtime behavior

1. The app determines the client location from geolocation.
2. It compares the client location to the target locations in the APP record data.
3. It returns the closest/best-matching response according to the APP record payload.

## Risks / operational notes

- Geolocation is approximate; distance-based decisions are only as good as the underlying location data.
- If APP record data is incomplete, the app may return no useful answer.

## Troubleshooting

- Verify the APP record contains valid JSON.
- Confirm the target locations and addresses are present in the APP payload.
