# Weighted Round Robin App

A DNS App for Technitium DNS Server that performs weighted selection of answers from APP record data.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Weighted selection** – answers are chosen according to weights in the APP record payload
- **Per-zone flexibility** – different zones can define different weighted sets

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

The app reads weighted answer data from the APP record JSON for the target name.

## Runtime behavior

1. The app reads weighted entries from the APP record payload.
2. It selects an answer based on the configured weights.
3. It returns the chosen A/AAAA/CNAME-style record data as an authoritative response.

## Risks / operational notes

- Misconfigured weights can skew traffic distribution.
- DNS caching affects perceived distribution; TTL matters.
- Keep weighted sets small and intentional.

## Troubleshooting

- Confirm the APP record contains valid JSON.
- Confirm the weighted entries contain the expected addresses/targets.