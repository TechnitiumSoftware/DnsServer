# Weighted Round Robin App

## Summary

A DNS App for Technitium DNS Server that performs weighted selection when returning multiple answers.

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

- The app uses weighted selection to choose which answer to return from multiple options.
- Higher-weighted entries are selected more frequently than lower-weighted entries.

## Risks / operational notes

- Uneven distribution can result if weights or data are misconfigured.
- DNS caching can cause answers to "stick" depending on client TTL handling.
- Debugging weighted distribution is difficult; test distribution patterns before production deployment.