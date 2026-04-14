# WhatIsMyDns App

A DNS App for Technitium DNS Server that returns the client's IP address for A, AAAA, and TXT queries.

## Overview

- **APP-record driven** – no root-level `dnsApp.config`
- **Client reflection** – answers with the client's source IP
- **Protocol-aware** – returns A for IPv4 clients and AAAA for IPv6 clients

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as an APP-record request handler.

## Configuration

`dnsApp.config` is not used by this app.

The app is configured by creating an APP record at the desired name. The APP record data itself is not used.

## Runtime behavior

- `A` queries return the client's IPv4 address when the client connects over IPv4.
- `AAAA` queries return the client's IPv6 address when the client connects over IPv6.
- `TXT` queries return the client's IP address as text.
- Other query types are not answered by this app.

## Risks / operational notes

- Reveals client IP information to the queried name.
- IPv4 and IPv6 clients receive different record types.
- Use carefully on internal or privacy-sensitive networks.

## Troubleshooting

- Confirm the APP record exists at the intended name.
- Confirm the query type is A, AAAA, or TXT.