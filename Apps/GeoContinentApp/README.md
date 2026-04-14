# GeoContinent App

## Summary

A DNS App for Technitium DNS Server that serves location-specific answers based on the **client continent**.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as: an APP-record request handler (answers are provided from the APP record context).

## Configuration

This app is **APP-record driven**.

- `dnsApp.config` is not used by this app.
- Configuration is provided via **APP record data** (JSON) in a zone.

### APP record JSON shape

The APP record data is a JSON object that maps:

- continent codes (for example `"NA"`, `"EU"`, `"AS"`) to response data
- an optional `"default"` entry used when there is no match

The exact per-continent value format is the app's APP-record contract (as interpreted by the app/server runtime); it is not a separate root config.

## Runtime behavior

- The app determines the client continent (based on the server's geolocation signal for the client).
- It selects the continent-specific entry, or falls back to `default` when present.

## Risks / operational notes

- Geolocation can be inaccurate or unavailable for some client IPs; ensure `default` is configured if you need deterministic behavior.
- Client-subnet related behavior (for example ECS) can change which continent is detected depending on deployment.

## Examples

Example APP record JSON skeleton:

```json
{
  "NA": { },
  "EU": { },
  "default": { }
}
