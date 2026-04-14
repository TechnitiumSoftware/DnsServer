# Default Records App

A DNS App for Technitium DNS Server that applies configurable default DNS records to authoritative zones during query post-processing.

This application enables system administrators to define reusable sets of DNS resource records and map them to specific zones or all zones using wildcard patterns. Default records are injected into DNS responses when the server returns authoritative answers, allowing for centralized management of common DNS records across multiple zones.

## Overview

The **Default Records App** extends Technitium DNS Server's core functionality by implementing a post-processor that intercepts authoritative DNS responses and conditionally injects predefined DNS resource records.

Key capabilities include:

- **Zone-to-Set Mapping**: Associate one or more record sets with specific zones, wildcard zones, or all zones
- **Reusable Record Sets**: Define named collections of DNS records in standard zone file format
- **Conditional Application**: Records are applied only to authoritative responses with `NOERROR` or `NXDOMAIN` codes
- **Dynamic Zone Resolution**: Supports wildcard zone mappings with automatic SOA-based zone detection
- **Type-Specific Filtering**: Default records are matched against query type and name before injection

This application is particularly useful for administrators managing multiple zones that share common DNS records such as SPF, DKIM, MX, or branding-related CNAME records.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and select the Default Records App package
4. Configure the `dnsApp.config` file according to your zone and record requirements

## Configuration

The application is configured using a JSON file named **`dnsApp.config`** located in the app's installation directory.

The configuration file defines three primary components: global settings, zone-to-set mappings, and record sets. All configuration changes require an app restart or reload to take effect.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableDefaultRecords` | boolean | `false` | Master switch to enable or disable default record processing |
| `defaultTtl` | unsigned integer | `3600` | Default TTL (in seconds) applied to records when not explicitly specified in zone file format |
| `zoneSetMap` | object | `{}` | Maps zone names (or patterns) to arrays of set names |
| `sets` | array | `[]` | Array of record set objects defining reusable DNS records |

### Zone-to-Set Mapping

The **`zoneSetMap`** object defines which record sets apply to which zones.

**Purpose**: Controls the scope of default record application by mapping zone names to one or more record sets.

**Key Features**:

- Exact zone matching (e.g., `"example.org"`)
- Wildcard suffix matching (e.g., `"*.net"` applies to all `.net` zones)
- Global wildcard (`"*"`) applies to all zones not matched by more specific rules
- Multiple sets can be assigned to a single zone

**JSON Example**:

```json
"zoneSetMap": {
  "*": ["global-set"],
  "*.com": ["commercial-set"],
  "*.net": ["network-set", "email-set"],
  "example.org": ["custom-set", "email-set"]
}
```

**Matching Logic**:

- The app performs hierarchical zone matching from most specific to least specific
- Exact zone names have priority over wildcard patterns
- Wildcard patterns (`*.parent.zone`) are checked before ascending to parent zones
- The global wildcard (`*`) is used only when no other match is found

### Record Set Configuration

Each object in the **`sets`** array defines a named collection of DNS resource records.

| Property | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique identifier for the set, referenced in `zoneSetMap` |
| `enable` | boolean | Yes | Whether this set is active; disabled sets are ignored even if mapped |
| `records` | array of strings | Yes | DNS resource records in standard zone file format |

**JSON Example**:

```json
"sets": [
  {
    "name": "email-set",
    "enable": true,
    "records": [
      "@ 3600 IN MX 10 mail.example.com.",
      "@ 3600 IN TXT \"v=spf1 a mx -all\"",
      "@ 3600 IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\""
    ]
  },
  {
    "name": "web-set",
    "enable": true,
    "records": [
      "www 3600 IN CNAME @",
      "ftp 3600 IN CNAME @"
    ]
  }
]
```

## DNS Record Format

Records in the `records` array must follow the **standard zone file syntax** as defined in RFC 1035.

**Format**: `<name> <ttl> <class> <type> <rdata>`

**Simple Example**:

```bind
@ 3600 IN A 192.0.2.1
www 7200 IN CNAME @
```

**Advanced Example**:

```bind
@ 3600 IN MX 10 mail.example.com.
@ 3600 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"
_dmarc 3600 IN TXT "v=DMARC1; p=quarantine; rua=mailto:reports@example.com"
mail 3600 IN A 192.0.2.10
mail 3600 IN AAAA 2001:db8::10
```

**Formatting Conventions**:

- The `@` symbol represents the zone apex (e.g., `example.com`)
- Names without a trailing dot are relative to the zone origin
- Names with a trailing dot are fully qualified domain names (FQDNs)
- TTL values are in seconds; if omitted, `defaultTtl` is applied
- TXT records must be enclosed in double quotes

## Example Configuration

```json
{
  "enableDefaultRecords": true,
  "defaultTtl": 3600,
  "zoneSetMap": {
    "*": ["global-defaults"],
    "*.com": ["commercial-branding"],
    "*.org": ["nonprofit-email"],
    "example.net": ["custom-example-net"]
  },
  "sets": [
    {
      "name": "global-defaults",
      "enable": true,
      "records": [
        "@ 3600 IN TXT \"v=spf1 -all\"",
        "www 3600 IN CNAME @"
      ]
    },
    {
      "name": "commercial-branding",
      "enable": true,
      "records": [
        "www 7200 IN CNAME @",
        "ftp 7200 IN CNAME @",
        "mail 3600 IN A 203.0.113.10"
      ]
    },
    {
      "name": "nonprofit-email",
      "enable": true,
      "records": [
        "@ 3600 IN MX 10 mail.example.org.",
        "@ 3600 IN TXT \"v=spf1 mx -all\"",
        "_dmarc 3600 IN TXT \"v=DMARC1; p=reject\""
      ]
    },
    {
      "name": "custom-example-net",
      "enable": false,
      "records": [
        "test 300 IN A 198.51.100.1"
      ]
    }
  ]
}
```

## Supported Resource Record Types

The Default Records App supports all DNS resource record types recognized by Technitium DNS Server and the TechnitiumLibrary zone file parser.

**Commonly Used Types**:

- **A**: IPv4 address record
- **AAAA**: IPv6 address record
- **CNAME**: Canonical name (alias) record
- **MX**: Mail exchange record
- **TXT**: Text record (SPF, DKIM, DMARC, verification tokens)
- **NS**: Name server record
- **SRV**: Service locator record
- **CAA**: Certification Authority Authorization record
- **PTR**: Pointer record (reverse DNS)

**Format Examples**:

```bind
@ 3600 IN A 192.0.2.1
@ 3600 IN AAAA 2001:db8::1
@ 3600 IN MX 10 mail.example.com.
@ 3600 IN TXT "v=spf1 mx -all"
_sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
@ 3600 IN CAA 0 issue "letsencrypt.org"
```

## How Default Record Processing Works

The application operates as a **DNS post-processor** that intercepts responses before they are sent to the client.

1. **Response Interception**: The app receives the DNS response generated by the server core
2. **Eligibility Validation**: Processing occurs only if:
   - `enableDefaultRecords` is set to `true`
   - The response has the **Authoritative Answer** flag set
   - The operation code is **StandardQuery**
   - The response code is **NOERROR** or **NXDOMAIN**
3. **Zone Matching**: The queried domain name is matched against `zoneSetMap` using hierarchical pattern matching
4. **Set Selection**: Mapped set names are retrieved; only enabled sets are processed
5. **Record Parsing**: Records from selected sets are parsed using the zone file parser with the resolved zone as origin
6. **Record Filtering**: Parsed records are filtered based on:
   - Matching DNS class (e.g., `IN`)
   - Matching record type or `CNAME`
   - Matching queried domain name (accounting for CNAME chains)
7. **Response Construction**: Matching records are appended to the answer section, and a new response datagram is returned
8. **Client Delivery**: The modified response is sent to the client

**Wildcard Zone Handling**:  
When a wildcard zone pattern is matched (e.g., `"*.net"`), the app queries the DNS server for the SOA record of the queried domain to determine the actual zone name before parsing records.

## Use Cases

1. **Centralized Email Security Policies:** Apply SPF, DKIM, and DMARC records to all zones under management without manual configuration per zone.
2. **Branding and Redirect Standardization:** Automatically create `www` CNAME records pointing to the zone apex across all commercial domains.
3. **Testing and Staging Environments:** Inject test-specific DNS records into staging zones without modifying production zone files.
4. **Multi-Tenant Hosting Platforms:** Apply provider-specific MX, NS, or CAA records to all customer zones using wildcard mappings.
5. **Compliance and Audit Requirements:** Ensure all zones contain mandatory TXT records for domain verification or security policies.
6. **Default Gateway and Service Discovery:** Provide SRV records for common services (e.g., LDAP, SIP) across an organization's internal zones.

## Troubleshooting

### Default Records Not Appearing in Responses

**Diagnostic Steps**:

1. Verify `enableDefaultRecords` is set to `true` in `dnsApp.config`
2. Confirm the queried zone matches a pattern in `zoneSetMap`
3. Check that the referenced set exists and has `enable: true`
4. Ensure the DNS server is returning an **authoritative answer** for the zone
5. Verify the response code is `NOERROR` or `NXDOMAIN`

**Check Logs**:

```bash
tail -f /var/log/dns/dns.log
```

Look for errors related to zone file parsing or record format issues.

### Records Applied to Wrong Zones

**Diagnostic Steps**:

1. Review the `zoneSetMap` for overlapping patterns
2. Verify wildcard patterns are correctly formatted (e.g., `"*.com"` not `".com"`)
3. Test zone matching logic by querying domains and checking applied sets
4. Ensure zone names in `zoneSetMap` are lowercase (case normalization is automatic)

**Configuration Check**:

Ensure specific zone mappings appear after wildcard patterns in the map to avoid confusion during manual review (although JSON object order does not affect matching).

### Zone File Parsing Errors

**Diagnostic Steps**:

1. Validate record syntax against RFC 1035 zone file format
2. Check for missing trailing dots on FQDNs
3. Verify TXT record content is enclosed in double quotes
4. Ensure TTL values are positive integers
5. Confirm record class is specified (usually `IN`)

**Example Error**:

```yaml
Invalid zone file entry: missing TTL or class
```

**Resolution**:

Correct the record format:

```json
"records": [
  "@ IN A 192.0.2.1"  // Missing TTL - uses defaultTtl
]
```

Should be:

```json
"records": [
  "@ 3600 IN A 192.0.2.1"
]
```

### Wildcard Zone Matching Not Resolving

**Diagnostic Steps**:

1. Verify the DNS server has an SOA record for the queried zone
2. Check that the zone is configured as authoritative
3. Test SOA query independently: `dig @server example.com SOA`
4. Review logs for SOA query failures during post-processing

**Resolution**:

Ensure the zone is properly configured as an authoritative zone in Technitium DNS Server before applying wildcard default records.
