# Typosquatting Detector for Technitium DNS Server

A DNS security plugin that detects and blocks look-alike domains associated with phishing and brand impersonation. The plugin evaluates similarity between queried domains and a high-reputation corpus and blocks near-miss variants before resolution.

## Detection model

The plugin builds a trusted corpus from the Majestic Million list plus an optional custom list. For each query it:

1. Normalizes to the registrable domain using Public Suffix rules.
2. Performs an O(1) Bloom filter check for known legitimate domains.
3. Runs fuzzy similarity matching against length-adjacent candidates for unknown domains.

Queries above the configured similarity threshold are classified as probable typosquats and blocked.

## Enforcement behavior

Suspicious domains receive an authoritative NXDOMAIN with SOA. Optional Extended DNS Error metadata and optional TXT blocking reports expose structured blocking details for logs and SIEM ingestion. Clean domains are not modified and resolve normally.

## Configuration

Example configuration:

```json
{
  "enable": true,
  "fuzzyMatchThreshold": 75,
  "customList": "/path/to/custom-domains.txt",
  "disableTlsValidation": false,
  "updateInterval": "30d",
  "allowTxtBlockingReport": true,
  "addExtendedDnsError": true
}
```

Key options

* fuzzyMatchThreshold (75–90): main sensitivity control. Lower values detect more variants but increase false positives.
* customList: one domain per line; add organization and brand domains you want treated as trusted.
* updateInterval: controls when the Majestic list is reprocessed; rebuilds are skipped when the file hash is unchanged.
* allowTxtBlockingReport / addExtendedDnsError: control operator visibility of blocking decisions.
* disableTlsValidation: test or lab use only.

## Deployment and risk considerations

Start with a conservative threshold (85–90) in production and observe blocks before lowering. False positives are most likely for domains visually similar to major brands but legitimate or newly emerging services. Mitigations include raising the threshold or adding the domain to the custom list.

This plugin is intended for recursive resolvers operated by security teams where DNS blocking is an accepted control point. Communicate expected behavior to users and support staff to avoid confusion when NXDOMAIN is enforcement rather than resolution failure.

## Acknowledgements

Uses [Majestic Million dataset](https://majestic.com/reports/majestic-million), [Nager Public Suffix parser](https://github.com/nager/Nager.PublicSuffix), [BloomFilter.NetCore](https://github.com/vla/BloomFilter.NetCore) and [FuzzySharp](https://github.com/JakeBayer/FuzzySharp) libraries, and the Technitium DNS Server app framework.
