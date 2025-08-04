# MISP Connector for Technitium DNS Server

A plugin that pulls malicious domain names from MISP feeds and enforces blocking in Technitium DNS.

It maintains in-memory blocklists with disk-backed caching and periodically refreshes from the source.

## Features

- Retrieves indicators of compromise (IOCs) aka. malicious domain names from a MISP server via its REST API.
- Handles paginated fetches with exponential backoff and retry on transient failures.
- Stores the latest blocklist in memory for fast lookup and persists it to disk for faster startup.
- Blocks matching DNS requests by returning NXDOMAIN or, for TXT queries when enabled, a human-readable blocking report.
- Optionally includes extended DNS error metadata.
- Configurable refresh interval and age window for which indicators are considered.
- Optional disabling of TLS certificate validation with explicit warning in logs.

## Configuration

Supply a JSON configuration like the following:

```json
{
	"enableBlocking": true,
	"mispServerUrl": "https://misp.example.com",
	"mispApiKey": "YourMispApiKeyHere",
	"disableTlsValidation": false,
	"updateInterval": "2h",
	"maxIocAge": "15d",
	"allowTxtBlockingReport": true,
	"paginationLimit": 5000,
	"addExtendedDnsError": true
}
```

- You can disable the app without uninstalling.
- You can disable TLS validation for test instances and homelabs, but **it is not recommended use this option in production**.
- The `maxIocAge` option is used for filtering IOCs wih `lastSeen` attributes on MISP. So, you can dynamically filter for recent campaigns.
- The `allowTxtBlockingReport` rewrites the response with a blocking report.
- The `addExtendedDnsError` is useful when logs are exported to a SIEM. The blocking report gets added to EDNS payload of the package.

# Acknowledgement

Thanks to everyone who has been part of or contributed to [MISP Project](https://www.misp-project.org/) for being an amazing resource.