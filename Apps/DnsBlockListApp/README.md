# DNS Block List App

A DNS App for Technitium DNS Server that implements **DNS-based Block Lists** (DNSBL) for IP addresses and domain names, based on RFC 5782. This application enables system administrators to create and maintain custom block lists that return standardized responses when queried.

## Overview

The DNS Block List App extends the core DNS Server functionality by providing **DNSBL query response capabilities** through APP records configured in primary or forwarder zones.

**Key capabilities:**

- **IP-based block lists** supporting both IPv4 and IPv6 addresses and networks
- **Domain-based block lists** with hierarchical matching
- **Customizable A and TXT record responses** per block list or per entry
- **Automatic file reloading** when block list files are modified
- **Multiple block list support** with independent configuration
- **RFC 5782 compliance** for DNS blacklist/whitelist implementation

This application provides administrative value for network operators implementing reputation-based filtering, threat intelligence integration, or compliance-driven access control at the DNS layer.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** section
3. Click **Install** or **Update** and select the DnsBlockListApp package
4. Configure the application using the `dnsApp.config` file or via the web interface

## Configuration

The application is configured using the `dnsApp.config` JSON file located in the application folder.

The configuration consists of an array of block list definitions under the `dnsBlockLists` property. Each block list operates independently and can be enabled or disabled without affecting others.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `dnsBlockLists` | array | `[]` | Array of block list configuration objects |

### Block List Configuration

Each entry in the `dnsBlockLists` array defines a single block list instance.

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *(required)* | Unique identifier for the block list, referenced in APP record data |
| `type` | string | `"ip"` | Block list type: `"ip"` or `"domain"` |
| `enabled` | boolean | `true` | Whether this block list is active |
| `responseA` | string | `"127.0.0.2"` | Default IPv4 address returned for blocked entries (A record response) |
| `responseTXT` | string | `null` | Default TXT record response; supports `{ip}` and `{domain}` placeholders |
| `blockListFile` | string | *(required)* | Path to block list file (relative to application folder or absolute) |

### IP Block List Format

IP block list files support both IPv4 and IPv6 addresses and network ranges.

**Format:** `network [A-response [TXT-response]]`

**Separator:** Space, tab, or pipe (`|`) character

**Examples:**

```text
# Single IPv4 address with default response
192.168.1.1

# IPv4 network with default response
192.168.0.0/24

# IPv4 address with custom A response
192.168.2.1	127.0.0.3

# IPv4 network with custom A and TXT responses
10.8.1.0/24	127.0.0.3	malware see: https://example.com/dnsbl?ip={ip}

# IPv6 network
2001:db8::/64
```

Lines beginning with `#` are treated as comments. Empty lines are ignored.

### Domain Block List Format

Domain block list files support exact domain matches with hierarchical parent zone matching.

**Format:** `domain [A-response [TXT-response]]`

**Separator:** Space, tab, or pipe (`|`) character

**Examples:**

```text
# Domain with default response
example.com

# Domain with custom A response
example.net	127.0.0.4

# Domain with custom A and TXT responses
malware.com	127.0.0.4	malware see: https://example.com/dnsbl?domain={domain}
```

Lines beginning with `#` are treated as comments. Empty lines are ignored.

## Example Configuration

```json
{
  "dnsBlockLists": [
    {
      "name": "ipblocklist1",
      "type": "ip",
      "enabled": true,
      "responseA": "127.0.0.2",
      "responseTXT": "https://example.com/dnsbl?ip={ip}",
      "blockListFile": "ip-blocklist.txt"
    },
    {
      "name": "domainblocklist1",
      "type": "domain",
      "enabled": true,
      "responseA": "127.0.0.2",
      "responseTXT": "https://example.com/dnsbl?domain={domain}",
      "blockListFile": "domain-blocklist.txt"
    }
  ]
}
```

## APP Record Configuration

To use the DNS Block List App, create an APP record in a zone with the following data structure:

```json
{
  "dnsBlockLists": [
    "ipblocklist1",
    "domainblocklist1"
  ]
}
```

The `dnsBlockLists` array contains the names of block lists (defined in `dnsApp.config`) that should be consulted for this APP record.

## How DNSBL Queries Work

The application processes DNSBL queries according to RFC 5782 specifications:

1. **Query Reception**: The DNS server receives a query for a subdomain under the APP record (e.g., `2.0.0.127.dnsbl.example.com`)

2. **Address/Domain Extraction**: The query name is parsed to extract either:
   - An IPv4 address (4 reversed octets)
   - An IPv6 address (32 reversed hex nibbles)
   - A domain name (standard label format)

3. **Block List Lookup**: The extracted address or domain is checked against each configured block list in order

4. **Response Generation**:
   - **For A queries**: Returns the configured A record (default or entry-specific)
   - **For TXT queries**: Returns the configured TXT record with placeholder substitution
   - **For other query types**: Returns NODATA response (SOA record from zone)

5. **NXDOMAIN Response**: If the address/domain is not found in any enabled block list, returns NXDOMAIN

## Supported Query Formats

### IPv4 Address Queries

Standard format with reversed octets:

```xml
<octet4>.<octet3>.<octet2>.<octet1>.<app-record-name>
```

Example: `1.168.192.10.dnsbl.example.com` queries for IP `10.192.168.1`

### IPv6 Address Queries

32 nibbles in reversed order (hex notation):

```xml
<nibble32>.<nibble31>....<nibble2>.<nibble1>.<app-record-name>
```

Example: Query for `2001:db8::1` would be formatted as reversed nibbles under the APP record name

### Domain Queries

Standard domain name format:

```xml
 <domain-name>.<app-record-name>
```

Example: `example.com.dnsbl.example.com` queries for domain `example.com`

The domain portion is read as-is from left to right before the APP record name; it is not reversed like IP-based DNSBL queries.

## RFC 5782 Compliance

This implementation adheres to **RFC 5782** (DNS Blacklists and Whitelists):

- **Test entries**: Both IP and domain block lists include RFC-mandated test entries (`127.0.0.2` for IP, `test` for domain)
- **Response format**: Standard A record responses in the `127.0.0.0/8` range
- **TXT record support**: Optional descriptive TXT records for blocked entries
- **NXDOMAIN semantics**: Unlisted entries return NXDOMAIN as specified

## Use Cases

1. **Spam Prevention:**  Deploy email server IP reputation lists to identify and block mail from known spam sources
2. **Threat Intelligence Integration:**  Load IP addresses and domains from threat feeds to prevent connections to malicious infrastructure
3. **Compliance Enforcement:**  Implement organizational policies blocking access to specific IP ranges or domain categories
4. **Network Abuse Mitigation:**  Maintain dynamic block lists of IPs exhibiting abusive behavior detected by intrusion prevention systems
5. **Content Filtering:**  Create domain block lists for categories requiring access restrictions (parental controls, workplace policies)
6. **Security Testing:**  Verify DNSBL integration in mail servers and security appliances using standardized test entries

## Automatic Reloading

The application monitors block list files for modifications and automatically reloads them when changes are detected.

- **Reload interval**: 60 seconds
- **Detection method**: File modification timestamp comparison
- **Logging**: Reload events and errors are written to the DNS Server log
- **Thread safety**: Atomic updates ensure consistent lookups during reload operations

No server restart or manual intervention is required when updating block list files.

## Response Priority

When an entry is found in a block list, the A and TXT responses are selected using the following priority:

1. **Entry-specific response** (defined in block list file)
2. **Block list default response** (defined in `dnsApp.config`)
3. **Application default** (`127.0.0.2`)

This allows granular control: global defaults can be overridden per block list, and individual entries can specify unique responses.

## Troubleshooting

### Block List Not Loading

**Symptoms**: Queries return NXDOMAIN for known blocked entries; log shows file read errors

**Resolution**:

1. Verify the `blockListFile` path in `dnsApp.config`
2. Check file permissions (application must have read access)
3. Review DNS Server logs for specific error messages
4. Ensure file uses UTF-8 encoding without BOM
5. Validate file format (check separator characters, syntax)

### Queries Return NXDOMAIN for Blocked Entries

**Symptoms**: Known blocked IPs/domains return NXDOMAIN instead of A/TXT records

**Resolution**:

1. Verify block list `enabled` property is `true`
2. Check APP record data includes correct block list name
3. Confirm query format matches DNSBL reverse notation (for IPs)
4. Review block list file for correct entry format
5. Check logs for parsing errors during block list load
6. Use DNS query logging to verify query name extraction

### TXT Records Not Returned

**Symptoms**: A record queries succeed, but TXT queries return NODATA

**Resolution**:

1. Verify `responseTXT` is configured in `dnsApp.config` or block list file
2. Check that TXT queries target the same name as successful A queries
3. Confirm entry-specific TXT response exists (if A response is entry-specific)
4. Review placeholder syntax (`{ip}` or `{domain}`)

### IPv6 Queries Not Working

**Symptoms**: IPv6 address queries return NXDOMAIN; IPv4 queries work correctly

**Resolution**:

1. Verify query name contains exactly 32 hex nibbles in reversed order
2. Check block list file contains IPv6 addresses or networks
3. Confirm network notation is correct (e.g., `2001:db8::/64`)
4. Test with standard IPv6 localhost: `::FFFF:7F00:2` (included as test entry)

### Domain Matching Not Working for Subdomains

**Symptoms**: Exact domains are blocked, but subdomains are not

**Behavior**: The domain block list implementation uses **hierarchical matching**. When querying for `sub.example.com`, the application will check:

1. `sub.example.com` (exact match)
2. `example.com` (parent zone)
3. `com` (parent zone)

**Resolution**:

1. Add parent domain to block list if subdomain blocking is desired
2. Verify domain in block list file is lowercase
3. Check domain format is valid per DNS specifications
