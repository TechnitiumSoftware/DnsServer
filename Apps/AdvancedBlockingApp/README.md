# Advanced Blocking App

A DNS App for [Technitium DNS Server](https://technitium.com/dns/) that provides advanced domain blocking capabilities with support for client-based group policies, multiple block list formats, and fine-grained control over blocking behavior.

## Overview

The Advanced Blocking App extends the DNS server's blocking capabilities by allowing administrators to:

- Create **client-based groups** with different blocking policies based on IP address, subnet, or local endpoint
- Use multiple types of block lists:  domain lists, regex patterns, and AdBlock-style lists
- Configure custom blocking responses (NXDOMAIN or custom IP addresses)
- Set up allow lists to whitelist specific domains
- Map clients to groups using network addresses or DNS endpoint identifiers

## ⚠️ Important Warning:  Overlap with Default Blocking

> **When this app is installed and enabled, it operates independently from the DNS server's built-in blocking feature.**
>
> The Advanced Blocking App does **NOT** use the block lists configured in the DNS server's Settings > Blocking page.  You must configure all block lists, allow lists, and blocking behavior within the app's own configuration.
>
> **You should choose one approach:**
>
> - **Option A:** Use the DNS server's built-in blocking (Settings > Blocking) and do NOT install this app
> - **Option B:** Install this app and configure ALL your blocking rules here, ignoring the built-in blocking settings
>
> Using both simultaneously may lead to confusion, as they process requests independently.  The app's blocking is evaluated during the request processing pipeline and may take precedence based on processing order.

## Installation

1. Open Technitium DNS Server web console
2. Navigate to **Apps** section
3. Click **App Store** and find the Advanced Blocking App to install
4. Configure the app by clicking on the **Config** button

## Configuration

The app is configured via a JSON configuration file (`dnsApp.config`). Below is a complete reference of all configuration options:

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enableBlocking` | boolean | `true` | Master switch to enable or disable all blocking |
| `blockingAnswerTtl` | integer | `30` | TTL (in seconds) for blocking responses |
| `blockListUrlUpdateIntervalHours` | integer | `24` | Hours between automatic block list updates |
| `blockListUrlUpdateIntervalMinutes` | integer | `0` | Additional minutes for update interval |
| `localEndPointGroupMap` | object | `{}` | Maps local DNS endpoints to group names |
| `networkGroupMap` | object | `{}` | Maps client networks/IPs to group names |
| `groups` | array | `[]` | Array of group definitions |

### Local Endpoint Group Mapping

Maps specific DNS server endpoints to groups.  Useful when running multiple DNS listeners (e.g., DoH, DoT, standard DNS) and wanting different policies for each.

```json
"localEndPointGroupMap": {
  "127.0.0.1": "bypass",
  "192.168.10.2:53": "bypass",
  "user1.dot.example.com":  "kids",
  "user2.doh.example.com:443": "bypass"
}
```

### Network Group Mapping

Maps client IP addresses or subnets to groups. More specific matches take precedence.

```json
"networkGroupMap": {
  "192.168.10.20": "kids",
  "192.168.10.0/24": "standard",
  "0.0.0.0/0": "everyone",
  "::/0": "everyone"
}
```

### Group Configuration

Each group defines its own blocking policy:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *required* | Unique group identifier |
| `enableBlocking` | boolean | `true` | Enable blocking for this group |
| `allowTxtBlockingReport` | boolean | `true` | Return blocking metadata in TXT queries and EDNS Extended DNS Error |
| `blockAsNxDomain` | boolean | `false` | Return NXDOMAIN instead of custom IP for blocked domains |
| `blockingAddresses` | array | `[]` | IP addresses to return for blocked A/AAAA queries |
| `allowed` | array | `[]` | Domains explicitly allowed (whitelist) |
| `blocked` | array | `[]` | Domains explicitly blocked |
| `allowListUrls` | array | `[]` | URLs to domain allow lists |
| `blockListUrls` | array | `[]` | URLs to domain block lists (string or object) |
| `allowedRegex` | array | `[]` | Regex patterns for allowed domains |
| `blockedRegex` | array | `[]` | Regex patterns for blocked domains |
| `regexAllowListUrls` | array | `[]` | URLs to regex allow list files |
| `regexBlockListUrls` | array | `[]` | URLs to regex block list files |
| `adblockListUrls` | array | `[]` | URLs to AdBlock-format lists |

### Block List URL Formats

Block list URLs can be specified as simple strings or as objects with additional options:

**Simple format:**

```json
"blockListUrls": [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
]
```

**Object format with custom options:**

```json
"blockListUrls": [
  {
    "url": "https://example.com/blocklist.txt",
    "blockAsNxDomain":  false,
    "blockingAddresses": ["192.168.10.2"]
  }
]
```

## Example Configuration

```json
{
  "enableBlocking": true,
  "blockingAnswerTtl": 30,
  "blockListUrlUpdateIntervalHours": 24,
  "blockListUrlUpdateIntervalMinutes": 0,
  "localEndPointGroupMap": {
    "127.0.0.1":  "bypass"
  },
  "networkGroupMap":  {
    "192.168.10.0/24": "kids",
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "everyone",
      "enableBlocking": true,
      "allowTxtBlockingReport":  true,
      "blockAsNxDomain": true,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed": [],
      "blocked":  ["example.com"],
      "allowListUrls": [],
      "blockListUrls": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      ],
      "allowedRegex": [],
      "blockedRegex": ["^ads\\."],
      "regexAllowListUrls": [],
      "regexBlockListUrls": [],
      "adblockListUrls": []
    },
    {
      "name":  "kids",
      "enableBlocking":  true,
      "allowTxtBlockingReport": true,
      "blockAsNxDomain": false,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed":  [],
      "blocked":  [],
      "allowListUrls": [],
      "blockListUrls": [
        {
          "url":  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
          "blockAsNxDomain": false,
          "blockingAddresses": ["192.168.10.2"]
        }
      ],
      "allowedRegex": [],
      "blockedRegex": [],
      "regexAllowListUrls":  [],
      "regexBlockListUrls": [],
      "adblockListUrls": []
    },
    {
      "name": "bypass",
      "enableBlocking": false,
      "allowTxtBlockingReport": true,
      "blockAsNxDomain": true,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed":  [],
      "blocked": [],
      "allowListUrls":  [],
      "blockListUrls": [],
      "allowedRegex": [],
      "blockedRegex": [],
      "regexAllowListUrls": [],
      "regexBlockListUrls":  [],
      "adblockListUrls": []
    }
  ]
}
```

## Supported Block List Formats

### Domain Block Lists

Standard hosts-file format or plain domain lists:

```syslog
# Comment line
0.0.0.0 ads.example.com
127.0.0.1 tracking.example.com
malware.example.com
```

### Regex Block Lists

One regex pattern per line:

```regex
# Block all subdomains starting with "ads"
^ads\. 
# Block tracking domains
.*tracking.*\.com$
```

### AdBlock Lists

As of v12.0, the AdBlock parser supports the majority of the AdGuard/AdBlock DNS-relevant syntax rather than only the plain `||domain^` form:

```
! Comment
||ads.example.com^
||tracking.example.com^$important
@@||safe.example.com^
||ads*.example.com^
*.telemetry.example.com
example.com$dnstype=A|AAAA
sub.example.com$denyallow=allowed.sub.example.com
||bad.example.com^$badfilter
||redirect.example.com^$dnsrewrite=127.0.0.1
||nx.example.com^$dnsrewrite=NXDOMAIN
/^ads[0-9]+\.example\.com$/$important
```

Supported modifiers (all other modifiers, e.g. `third-party`, `domain=`, `doc`, `all`, `match-case`, `client=`, `ctag=`, `app=`, are recognized and silently ignored rather than invalidating the rule):

| Modifier | Behavior |
| --- | --- |
| `$important` | Rule takes precedence over any rule (allow or block) without `$important` in any list of the group. Between two conflicting `$important` rules, block wins. |
| `$badfilter` | Cancels other rules (of the same allow/block polarity) in the **same list** whose domain/pattern text matches. This is an approximation of AdGuard's exact-rule-text `$badfilter` matching (cross-list cancellation is not supported). |
| `$dnstype=TYPE\|TYPE...` | Restricts the rule to only apply for the listed DNS query types (e.g. `A`, `AAAA`, `HTTPS`). Negated entries (`~TYPE`) are not modeled and are treated as a positive match. |
| `$denyallow=domain\|domain...` | Excludes the listed domains (and their subdomains) from an otherwise-matching wildcard/regex rule. |
| `$dnsrewrite=value` | Returns a custom answer instead of the group's default blocking response. Supported forms: a bare IP address (`$dnsrewrite=127.0.0.1`), a typed IP (`$dnsrewrite=AAAA;::1`), and the `NOERROR`/`NXDOMAIN`/`REFUSED` response-code keywords. CNAME/TXT/HTTPS/SVCB/MX rewrite targets require re-invoking the resolver and are **not supported** — such rules fall back to the group's normal default blocking behavior. |

Also supported:

- **Wildcards** in the domain portion (`||ads*.example.com^`, `*.ads.example.com`) via automatic regex compilation (a lone `*.` prefix is optimized to the same fast path as a plain domain rule).
- **Regex rules** (`/pattern/` or `/pattern/$modifiers`), matched directly against the query's domain name.
- **Bare-domain fallback**: a line containing just a hostname (with optional wildcard and optional trailing `$modifiers`), similar to a hosts-file entry but without the `0.0.0.0` prefix.

**Explicitly out of scope** (since this app only ever sees a DNS query, never a URL or page content):

- Cosmetic/element-hiding rules (`##`, `#@#`, `#$#`, `#%#`, `#?#`, `$$`) — detected and skipped.
- Single-pipe URL-anchor rules (`|https://example.com/path`) and any `||domain^/path`-style path-qualified rule.
- `$dnsrewrite=` targets other than an IP address or a bare response-code keyword (CNAME/TXT/HTTPS/SVCB/MX).
- Exact-rule-text `$badfilter` matching and cross-list `$badfilter` cancellation (approximated instead, see above).
- `$client=`/`$ctag=`/`$app=` enforcement (parsed but ignored).


## How Blocking Works

1. **Group Selection**: When a DNS request arrives, the app determines which group applies based on:
   - First, local endpoint mapping (`localEndPointGroupMap`)
   - Then, client IP/network mapping (`networkGroupMap`)
   - More specific network matches take precedence

2. **Allow Check**: If the domain matches any allow list (static, URL-based, regex, or AdBlock whitelist), the request is NOT blocked — unless a higher-priority `$important` AdBlock block rule matches, in which case the block wins.

3. **Block Check**: If the domain matches any block list, the app returns:
   - The custom answer from `$dnsrewrite=` if the matched AdBlock rule carries one and it's a supported form
   - `NXDOMAIN` if `blockAsNxDomain` is `true`
   - Configured `blockingAddresses` for A/AAAA queries
   - NO DATA response for other query types

4. **Blocking Report**: When `allowTxtBlockingReport` is enabled:
   - TXT queries for blocked domains return metadata about why the domain was blocked
   - EDNS Extended DNS Error option is included in responses

## Use Cases

1. **Parental Controls**: Create a "kids" group with stricter blocking for children's devices
2. **Guest Network**: Apply different policies to guest WiFi subnet
3. **IoT Isolation**: Block telemetry for IoT devices on a specific VLAN
4. **Multi-tenant DNS**: Different blocking policies for different clients sharing the same DNS server
5. **DoH/DoT Differentiation**: Apply different policies based on DNS transport protocol

## Troubleshooting

### Block lists not updating

- Check the DNS server logs for download errors
- Verify the URLs are accessible from the server
- Ensure the server has internet connectivity (or proxy configured)

### Domains not being blocked

1. Verify the client IP maps to the correct group
2. Check if the domain is in an allow list
3. Confirm `enableBlocking` is `true` at both root and group level
4. Review the group's block list configuration

### Testing blocking

Query a TXT record for a blocked domain from the client IP address to see the blocking report:

```bash
dig TXT blocked-domain.com @your-dns-server
```
