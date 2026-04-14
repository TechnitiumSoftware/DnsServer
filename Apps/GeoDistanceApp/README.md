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
