# NxDomain Override App

A DNS App for Technitium DNS Server that enables advanced NXDOMAIN response handling with customizable override rules based on client groups, query patterns, and response policies.

This app provides fine-grained control over DNS responses for non-existent domains, allowing administrators to redirect users based on group membership, query characteristics, or network policies. It extends the core DNS server with intelligent NXDOMAIN interception and override capabilities suitable for enterprise environments, ISPs, and managed network deployments.

## Overview

The **NxDomain Override App** extends Technitium DNS Server's core query resolution logic by intercepting NXDOMAIN responses and applying configurable override policies before returning the final response to clients.

**Key capabilities:**

- **Group-based policy enforcement** — Apply different override rules to different client groups based on IP addresses, subnets, or TSIG authentication
- **Pattern-based query filtering** — Match queries using regex, domain lists, or allowed/blocked patterns
- **Flexible response override** — Return custom A/AAAA records, CNAME redirects, or block pages instead of NXDOMAIN
- **Granular response control** — Configure TTL, response codes, and additional records per policy
- **Logging and diagnostics** — Track matched queries, applied policies, and override decisions

This app is particularly valuable for administrators implementing split-horizon DNS, content filtering, brand protection, or custom landing pages for typo domains.

## ⚠️ Important Warning: NXDOMAIN Response Handling

This app **intercepts and modifies NXDOMAIN responses** returned by the DNS server. Improper configuration can result in:

- Breaking legitimate negative caching behavior
- Creating DNS resolution loops
- Interfering with DNSSEC validation
- Causing client application failures that depend on accurate NXDOMAIN responses

**Exclusive usage guidance:**

- **Option A:** Use this app for **override-based policies** where you need custom responses for non-existent domains
- **Option B:** Use **core DNS server blocking** or **custom zone files** for standard domain blocking scenarios

**Processing order implications:**

This app operates during the **post-resolution phase**, after the DNS server has determined the query would return NXDOMAIN. It will **not** affect queries that return valid responses, SERVFAIL, or other non-NXDOMAIN status codes.

## Installation

1. Open the Technitium DNS Server web console
2. Navigate to **Apps** in the main menu
3. Click **Install/Update** and upload the NxDomainOverrideApp package, or install from the app store
4. Configure the app using the configuration file or web interface

## Configuration

The app is configured using a JSON configuration file named **`dnsApp.config`**, stored in the app's installation directory.

The configuration consists of a root object containing global settings and an array of override policies organized into groups. Each group can contain multiple rules evaluated sequentially.

**All configuration is mandatory unless explicitly marked optional.**

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch to enable or disable the entire app |
| `defaultAction` | string | `"allow"` | Default action when no rules match: `"allow"` (return original NXDOMAIN) or `"block"` (return REFUSED) |
| `logging` | boolean | `false` | Enable detailed logging of matched queries and applied policies |
| `logLevel` | string | `"info"` | Logging verbosity: `"debug"`, `"info"`, `"warning"`, `"error"` |
| `groups` | array | `[]` | Array of client group objects, each containing selection criteria and override rules |

### Client Group Configuration

Each group defines a set of clients (by IP, subnet, or TSIG key) and the override rules to apply to queries from those clients.

**Group Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *required* | Human-readable group identifier for logging and diagnostics |
| `enabled` | boolean | `true` | Enable or disable this group without removing configuration |
| `priority` | integer | `0` | Evaluation priority (lower numbers evaluated first; groups with same priority evaluated in definition order) |
| `selectors` | object | *required* | Client selection criteria (IP ranges, subnets, TSIG keys) |
| `rules` | array | *required* | Array of override rule objects evaluated sequentially |

**Selector Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `ipRanges` | array | `[]` | Array of IP addresses or CIDR subnets (IPv4 and IPv6 supported) |
| `tsigKeys` | array | `[]` | Array of TSIG key names for authenticated queries |
| `matchAll` | boolean | `false` | If `true`, this group matches all clients (use with caution) |

### Override Rule Configuration

Each rule defines query matching criteria and the response override behavior.

**Rule Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *required* | Rule identifier for logging |
| `enabled` | boolean | `true` | Enable or disable this rule |
| `priority` | integer | `0` | Rule evaluation priority within the group |
| `queryMatch` | object | *required* | Query matching criteria (domain patterns, regex, lists) |
| `action` | string | *required* | Override action: `"override"`, `"allow"`, `"block"` |
| `response` | object | *conditional* | Response configuration (required if `action` is `"override"`) |

**Query Match Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `domainPatterns` | array | `[]` | Array of domain match patterns (supports `*` wildcard, e.g., `*.example.com`) |
| `regex` | string | `null` | Regular expression for advanced domain matching (evaluated if `domainPatterns` empty) |
| `domainLists` | array | `[]` | Array of external domain list file paths (one domain per line, `#` for comments) |
| `matchType` | string | `"any"` | Match logic: `"any"` (OR), `"all"` (AND) |
| `caseSensitive` | boolean | `false` | Enable case-sensitive domain matching |

**Response Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `type` | string | *required* | Response record type: `"A"`, `"AAAA"`, `"CNAME"`, `"SOA"`, `"TXT"` |
| `records` | array | *required* | Array of response record values (format depends on `type`) |
| `ttl` | integer | `300` | Time-to-live (seconds) for response records |
| `rcode` | string | `"NoError"` | DNS response code: `"NoError"`, `"NxDomain"`, `"Refused"`, `"ServerFailure"` |
| `additionalRecords` | array | `[]` | Array of additional record objects to include in response |

### Additional Record Configuration

Used to include extra DNS records in override responses.

**Additional Record Object Properties:**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *required* | Record name (domain) |
| `type` | string | *required* | Record type: `"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, `"NS"` |
| `value` | string | *required* | Record value (format depends on type) |
| `ttl` | integer | `300` | Time-to-live for this record |

## Domain Pattern Formats

The app supports multiple domain matching formats for flexible query filtering.

### Simple Wildcard Patterns

```
*.example.com        # Matches any subdomain of example.com
example.*            # Matches example with any TLD
test-*.example.com   # Matches test- prefix with any suffix
```

### Regular Expression Patterns

```json
{
  "regex": "^(test|staging)-.*\\.example\\.com$"
}
```

Matches domains like:
- `test-app.example.com`
- `staging-service.example.com`

Regular expressions must use standard POSIX syntax. The `^` and `$` anchors are recommended for precise matching.

### Domain List Files

External text files containing one domain per line:

```
# Typo domains to redirect
exampl.com
exmaple.com
exampel.com
```

Paths are relative to the app installation directory or absolute filesystem paths.

## Example Configuration

```json
{
  "enabled": true,
  "defaultAction": "allow",
  "logging": true,
  "logLevel": "info",
  "groups": [
    {
      "name": "Corporate Network",
      "enabled": true,
      "priority": 10,
      "selectors": {
        "ipRanges": [
          "10.0.0.0/8",
          "192.168.1.0/24",
          "2001:db8::/32"
        ],
        "tsigKeys": []
      },
      "rules": [
        {
          "name": "Redirect Typo Domains",
          "enabled": true,
          "priority": 1,
          "queryMatch": {
            "domainPatterns": [
              "*.exmaple.com",
              "*.exampl.com"
            ],
            "matchType": "any",
            "caseSensitive": false
          },
          "action": "override",
          "response": {
            "type": "A",
            "records": ["192.168.1.100"],
            "ttl": 60,
            "rcode": "NoError"
          }
        },
        {
          "name": "Block Malicious Patterns",
          "enabled": true,
          "priority": 2,
          "queryMatch": {
            "regex": "^.*\\.(tk|ml|ga)$",
            "matchType": "any"
          },
          "action": "block",
          "response": {
            "type": "A",
            "records": ["0.0.0.0"],
            "ttl": 3600,
            "rcode": "NoError"
          }
        }
      ]
    },
    {
      "name": "Guest Network",
      "enabled": true,
      "priority": 20,
      "selectors": {
        "ipRanges": ["192.168.100.0/24"],
        "tsigKeys": []
      },
      "rules": [
        {
          "name": "Portal Redirect",
          "enabled": true,
          "priority": 1,
          "queryMatch": {
            "domainPatterns": ["*"],
            "matchType": "any"
          },
          "action": "override",
          "response": {
            "type": "A",
            "records": ["192.168.100.1"],
            "ttl": 30,
            "rcode": "NoError",
            "additionalRecords": [
              {
                "name": "portal.guest.local",
                "type": "A",
                "value": "192.168.100.1",
                "ttl": 30
              }
            ]
          }
        }
      ]
    }
  ]
}
```

## Supported Domain List Formats

### Plain Text Format

One domain per line, `#` for comments:

```
# Typo domain list
example.co
exampel.com

# Additional entries
test.com
```

### Comma-Separated Values (CSV)

```
domain,category,priority
example.co,typo,high
exampel.com,typo,high
```

The app reads the first column as the domain name.

### Wildcard Entries in Lists

```
*.malicious.com
*.phishing.net
```

Wildcard patterns are supported in list files.

## How Query Override Works

The app processes queries through the following pipeline:

1. **Client Group Selection** — Incoming DNS queries are matched against group selectors (IP ranges, TSIG keys). Groups are evaluated in priority order (lowest first). The first matching group is selected.

2. **Query Evaluation** — Within the selected group, rules are evaluated sequentially by priority. For each rule, the query domain is matched against `domainPatterns`, `regex`, or `domainLists` according to the `matchType` setting.

3. **Action Determination** — If a rule matches, its `action` is applied:
   - `"override"` — Replace NXDOMAIN with custom response
   - `"allow"` — Return original NXDOMAIN response (stop processing)
   - `"block"` — Return configured block response or REFUSED

4. **Response Construction** — For `"override"` actions, the app constructs a DNS response using the `response` object: record type, values, TTL, RCODE, and any additional records.

5. **Logging and Reporting** — If logging is enabled, the app records the matched group, rule, query, and action taken. Log entries include timestamps, client IP, query name, and override details.

If no rules match, the `defaultAction` setting determines whether to return the original NXDOMAIN or apply a global block policy.

## Use Cases

### Typo Domain Redirection

Redirect common misspellings of corporate domains to the correct website or an informational landing page, improving user experience and reducing support calls.

### Brand Protection

Intercept queries for domains similar to registered trademarks and redirect users to legitimate properties or warning pages, mitigating phishing and fraud risks.

### Guest Network Portal Enforcement

Override NXDOMAIN responses on guest networks to redirect all failed DNS queries to a captive portal or acceptable use policy page.

### Development and Staging Environment Isolation

Apply different override rules to internal developer networks, returning custom responses for non-existent staging or test domains without affecting production clients.

### Content Filtering for Specific Client Groups

Block or redirect queries for known malicious or inappropriate domains based on client group membership, supporting differentiated security policies across network segments.

### ISP Value-Added Services

Provide ISP customers with custom search landing pages or advertising redirects for NXDOMAIN responses, while allowing opt-out through client group exclusion.

## Troubleshooting

### Override Not Applied to Expected Queries

**Diagnostic Steps:**

1. Enable logging (`"logging": true`, `"logLevel": "debug"`) and restart the DNS server
2. Review logs for query processing entries
3. Verify the query returns NXDOMAIN before app processing (use `dig` or `nslookup` with trace)
4. Confirm client IP matches a group selector
5. Check rule priorities and `enabled` flags

**Common Causes:**

- Query does not result in NXDOMAIN (e.g., returns valid A record or SERVFAIL)
- Client IP not in any group selector range
- Rule `enabled` set to `false`
- Domain pattern or regex does not match query

**Resolution:**

- Adjust group selectors to include client IP or subnet
- Review domain matching patterns (test regex with `regex101.com` or similar tools)
- Verify NXDOMAIN condition using direct server query

### Incorrect Response Records Returned

**Diagnostic Steps:**

1. Check the `response.type` and `response.records` array in matched rule
2. Verify record format matches DNS record type (e.g., A records require IPv4 addresses)
3. Review logs for response construction warnings
4. Test with `dig +norecurse @server-ip domain.name` to isolate server response

**Common Causes:**

- Malformed record values (e.g., invalid IP address format)
- Incorrect `type` for intended record (e.g., `AAAA` with IPv4 address)
- Conflicting additional records with same name

**Resolution:**

- Validate record values against DNS record type specifications (RFC 1035 for A/CNAME, RFC 3596 for AAAA)
- Use `dig` to verify response matches expected structure
- Remove or correct conflicting additional records

### High Memory or CPU Usage

**Diagnostic Steps:**

1. Review number of groups and rules
2. Check domain list file sizes
3. Inspect regex complexity (backtracking patterns)
4. Monitor logs for excessive rule evaluation

**Common Causes:**

- Very large domain list files (>100,000 entries)
- Inefficient regular expressions with catastrophic backtracking
- Too many groups or rules causing excessive evaluation overhead

**Resolution:**

- Split large domain lists into smaller files or use domain pattern wildcards
- Simplify regular expressions; avoid nested quantifiers (e.g., `.*.*`)
- Consolidate similar rules; reduce total rule count
- Increase group priority separation to limit rule evaluation

### Domain Lists Not Loading

**Diagnostic Steps:**

1. Verify file path in `domainLists` array (relative or absolute)
2. Check file permissions (read access for DNS server process user)
3. Review logs for file I/O errors
4. Confirm file format (plain text, one domain per line)

**Commands:**

```bash
# Check file existence and permissions
ls -l /path/to/domain-list.txt

# Verify file format
head -n 10 /path/to/domain-list.txt

# Test read access as DNS server user
sudo -u technitium cat /path/to/domain-list.txt
```

**Resolution:**

- Use absolute paths for domain list files
- Set file permissions to `644` or readable by DNS server user
- Validate file format (UTF-8 encoding, Unix line endings)

### Logging Not Recording Matched Queries

**Diagnostic Steps:**

1. Confirm `"logging": true` in root configuration
2. Check `logLevel` setting (must be `"info"` or `"debug"`)
3. Verify DNS server log output location
4. Restart DNS server after configuration changes

**Common Causes:**

- Logging disabled globally or `logLevel` set to `"error"`
- Log output not visible in console (check log file configuration)
- Configuration changes not applied (server not restarted)

**Resolution:**

- Set `"logging": true` and `"logLevel": "debug"` for maximum verbosity
- Locate DNS server log file (typically `/var/log/technitium/` or configured path)
- Restart Technitium DNS Server service: `systemctl restart technitium-dns-server`

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

For more information, see the LICENSE file in the project repository or visit https://www.gnu.org/licenses/gpl-3.0.html.