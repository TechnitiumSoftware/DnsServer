# GeoDistance App

## Summary

A DNS App for Technitium DNS Server that returns answers based on **distance/proximity**.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as: an APP-record request handler (answers are provided from the APP record context).

## Configuration

This app is **APP-record driven**.

- `dnsApp.config` is not used by this app.
- Configuration is provided via **APP record data** (JSON) in a zone.

### APP record JSON

Refer to the APP record editor/template in the Technitium DNS Server UI for the exact JSON schema expected by this app.

## Runtime behavior

- The app calculates distance from the client (based on geolocation) to each target/endpoint in the APP record data.
- It selects the closest endpoint(s) according to the decision logic encoded in the APP record.

## Risks / operational notes

- Accuracy depends on geolocation precision and target coordinate accuracy.
- Ties and edge cases should be handled by the APP record data logic.
- Different zones/records can have different distance maps and selection rules.
