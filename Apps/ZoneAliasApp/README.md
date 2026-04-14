# Zone Alias App

A DNS App for Technitium DNS Server that enables aliasing of DNS zones by mapping multiple zone names to return identical resource records from a primary zone.

This application intercepts authoritative DNS queries and rewrites zone names based on configured alias mappings, allowing administrators to serve the same DNS records for multiple domain names without zone duplication.

## Overview

The **Zone Alias App** extends the core DNS server's authoritative response handling by implementing zone aliasing functionality. When a DNS query matches a configured alias, the app internally rewrites the query to the primary zone, retrieves records, and transforms them back to match the original queried zone name.

**Key capabilities:**

- **Zone-level aliasing** – Map multiple domain names to a single authoritative zone
- **Dynamic record rewriting** – Automatically converts DNS resource records to match the alias zone
- **Hierarchical zone matching** – Supports aliasing at any level of the DNS hierarchy
- **Selective enablement** – Can be enabled or disabled without removing configuration
- **Internal and external zone support** – Works with both locally hosted and external zones

This application provides significant administrative value by reducing zone management overhead and enabling multi-domain DNS strategies without record duplication.

## Important Warning: Zone Duplication

> This app provides an alternative to maintaining multiple identical zones. Administrators must choose between:
>
> **Option A:** Use native DNS zone management with separate zone files for each domain  
> **Option B:** Use the Zone Alias App to map multiple domains to a single zone
>
> Using both approaches simultaneously for the same domains may result in conflicting responses, unpredictable query resolution, and operational confusion.

The Zone Alias App operates at the authoritative request handler level with configurable preference ordering. Ensure the `appPreference` value is set appropriately relative to other DNS apps to control processing order.

## Installation

1. Open the Technitium DNS Server web console.
2. Navigate to **Apps** in the main menu.
3. Click **Install** and select the Zone Alias App package, or use **Update** if upgrading an existing installation.
4. Configure the application using the `dnsApp.config` file as described below.

## Configuration

The application is configured using the `dnsApp.config` file in JSON format. The configuration structure supports global aliasing settings and zone-specific alias mappings.

All configuration changes require app reload or DNS server restart to take effect.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `appPreference` | byte | `10` | Processing order priority for this app relative to other DNS apps. Lower values execute earlier in the request pipeline. |
| `enableAliasing` | boolean | `true` | Global flag to enable or disable zone aliasing functionality. When `false`, all aliasing is disabled regardless of configured mappings. |
| `zoneAliases` | object | (empty) | Object defining zone alias mappings. Each property name is the primary zone, with an array of alias zone names as the value. |

### Zone Alias Mapping

The `zoneAliases` configuration object maps primary zones to their aliases. Each property represents one primary zone with one or more alias zones.

**Structure:**

```json
{
  "zoneAliases": {
    "primary-zone.com": ["alias1.com", "alias2.net"],
    "another-zone.org": ["mirror.org"]
  }
}
```

- **Property name** (e.g., `primary-zone.com`): The authoritative zone containing the actual DNS records
- **Property value** (array): List of alias zone names that will return records from the primary zone

**Behavior:**

- Queries to `alias1.com` or `alias2.net` will return records from `primary-zone.com`
- Record names are automatically rewritten to match the queried alias zone
- Subdomain queries are supported (e.g., `www.alias1.com` → `www.primary-zone.com`)

## Example Configuration

```json
{
  "appPreference": 10,
  "enableAliasing": true,
  "zoneAliases": {
    "example.com": ["example.net", "example.org"],
    "company.internal": ["company.local", "company.lan"],
    "service.cloud": ["service.backup"]
  }
}
```

This configuration:

- Executes with default priority (`10`)
- Enables aliasing globally
- Configures three primary zones with multiple aliases:
  - `example.net` and `example.org` resolve using records from `example.com`
  - `company.local` and `company.lan` resolve using records from `company.internal`
  - `service.backup` resolves using records from `service.cloud`

## How Zone Aliasing Works

The Zone Alias App processes DNS queries through the following pipeline:

1. **Query Interception** – The authoritative request handler receives the incoming DNS query and extracts the queried domain name (QNAME).
2. **Alias Matching** – The app performs hierarchical matching from the QNAME down to parent zones, checking if the domain or any parent domain is configured as an alias.
3. **Query Rewriting** – If an alias match is found, the app rewrites the query by substituting the alias zone with the primary zone name while preserving subdomain prefixes.
4. **Internal Resolution** – The rewritten query is submitted to the DNS server's `DirectQueryAsync` method for authoritative resolution against the primary zone.
5. **Record Transformation** – All returned DNS resource records (Answer, Authority, Additional sections) are converted by replacing the primary zone name with the original alias zone name.
6. **Response Generation** – A new DNS response datagram is constructed with the transformed records and returned to the client, maintaining all original DNS flags and metadata.

If aliasing is disabled, no alias is matched, or query processing fails, the app returns control to the DNS server's standard resolution pipeline.

## Use Cases

1. **Multi-brand domain consolidation:** Organizations serving multiple brand domains (e.g., `brand-a.com`, `brand-b.net`) can maintain DNS records in a single zone while presenting different domain names to users.
2. **Geographic or regional domain mirroring:** Enterprises with region-specific domains (e.g., `service.us`, `service.eu`, `service.asia`) can serve identical infrastructure records without zone duplication.
3. **Migration and transition scenarios:** During domain migrations, legacy domains can be aliased to new domains, allowing both to resolve identically while DNS records are consolidated.
4. **Development and staging environments:** Internal zones (e.g., `app.production`) can be aliased to staging or testing domains (`app.staging`, `app.dev`) to mirror production DNS configuration.
5. **ISP multi-domain management:** Service providers managing customer domains can reduce zone file proliferation by aliasing customer domains to template zones.
6. **Disaster recovery and failover:** Backup domain names can be pre-configured as aliases to primary zones, enabling rapid DNS-level failover by updating delegation or NS records.

## Troubleshooting

### Alias Not Resolving

**Symptoms:** DNS queries to alias zones return NXDOMAIN or no records.

**Diagnostic steps:**

1. Verify `enableAliasing` is set to `true` in `dnsApp.config`.
2. Check that the alias zone is correctly listed in the `zoneAliases` configuration object.
3. Confirm the primary zone exists and is authoritative on the DNS server.
4. Review DNS server logs for exceptions or timeout errors from the Zone Alias App.
5. Test resolution of the primary zone directly to ensure records exist.

**Configuration check:**

```json
{
  "enableAliasing": true,
  "zoneAliases": {
    "primary.com": ["alias.com"]
  }
}
```

Ensure the alias zone (`alias.com`) does not exist as a separate zone on the DNS server.

### Records Returned with Wrong Zone Name

**Symptoms:** DNS responses contain records with the primary zone name instead of the alias zone name.

**Diagnostic steps:**

1. Verify the Zone Alias App is loaded and active in the DNS server Apps list.
2. Check DNS server logs for errors in the `ConvertRecords` function.
3. Confirm the `appPreference` value allows the app to execute in the correct order.
4. Test with simple A or AAAA records first to isolate complex record types.

This issue may indicate a malfunction in record transformation logic or app loading failure.

### ServerFailure Responses for Alias Queries

**Symptoms:** Queries to alias zones return SERVFAIL (response code 2).

**Diagnostic steps:**

1. Review DNS server application logs for exception messages from the Zone Alias App.
2. Check for timeout exceptions indicating the primary zone is unresponsive.
3. Verify the primary zone is authoritative and not delegated to external nameservers.
4. Test the primary zone resolution using the DNS server's query log or diagnostic tools.

**Common causes:**

- Primary zone is configured as a stub or forwarder zone instead of authoritative
- Primary zone file is malformed or contains errors
- DNS server internal query timeout (default timeouts apply)

### Conflicting Responses Between Alias and Native Zones

**Symptoms:** Inconsistent responses when the same domain is configured both as an alias and as a native zone.

**Diagnostic steps:**

1. Verify the domain does not exist as a separate authoritative zone on the DNS server.
2. Check the `appPreference` value to understand processing order.
3. Disable the Zone Alias App temporarily to confirm if the conflict resolves.

**Resolution:**

Remove either the native zone or the alias configuration. Operating both simultaneously for the same domain violates DNS consistency requirements.
