# WhatIsMyDns App

## Summary

A DNS App for Technitium DNS Server that returns the client's IP address for **A**, **AAAA**, and **TXT** queries.

## Integration / extension points

- Implements: `IDnsApplication`, `IDnsAppRecordRequestHandler`
- Runs as: an APP-record request handler (answers are provided from the APP record context).

## Configuration

This app is **APP-record driven**.

- `dnsApp.config` is not used by this app.
- Create an **APP record** in a zone for the name you want to answer (for example, `whoami.example.com`).
- The APP record data is not used; configuration is implicit.

## Runtime behavior

For requests that match the APP record name (or wildcard APP record names as supported by the DNS app runtime):

- Query type `A`: returns an A record containing the client's IPv4 address (only when the client connects over IPv4).
- Query type `AAAA`: returns an AAAA record containing the client's IPv6 address (only when the client connects over IPv6).
- Query type `TXT`: returns a TXT record containing the client's IP address as text.
- Other query types: no response from this app.

## Risks / operational notes

- **Privacy**: reveals client IP address to the domain being queried.
- **Asymmetric behavior**: different responses based on transport (IPv4 vs IPv6); may confuse clients with both transports.
- **Internal IP disclosure**: can leak internal IP addresses if used on internal domains accessed by internal clients.