# Automatic TLS certificates (ACME, DNS-01)

Technitium DNS Server can obtain, install and renew its own TLS certificate for:

- the **web console** (HTTPS);
- **DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC**.

It works with any ACME certificate authority: Let's Encrypt, ZeroSSL, Google Trust Services, or an internal one such as step-ca. It uses **DNS-01** validation, so the server doesn't need to be reachable from the internet. Only the domain's public DNS has to be updatable.

Everything is configured in **Settings > Certificates (ACME)**.

## How it works

1. The server registers an account with the certificate authority (CA), using an ECDSA P-256 account key stored on the server.
2. It orders a certificate for the configured names and, for each name, publishes the challenge TXT record `_acme-challenge.<name>` through the selected **DNS-01 provider**.
3. It looks the name up through **public resolvers** (default 1.1.1.1, 8.8.8.8, 9.9.9.9) to find the zone's public authoritative name servers. It then queries those servers directly until the record is visible on all of them.
   - Servers that don't answer at all, such as IPv6 addresses on a network without IPv6, are skipped.
   - If none of them answers within 30 seconds, the check is skipped with a warning, and the CA validates directly. This happens when the zone's public name server is this network's own public IP and the router doesn't support NAT hairpin.
4. It asks the CA to validate, finalizes the order with a fresh private key (ECDSA P-256 or RSA 2048), downloads the certificate chain, and removes the TXT records.
5. It saves `config/acme/certificate.pfx` and installs it for the web service and/or the encrypted DNS protocols. Renewals replace the same file. The existing certificate reload picks them up, and a Cluster node republishes its certificate to the Cluster automatically.

A renewal check runs 2 minutes after startup and then every 6 hours. A certificate is renewed when:

- it expires within **Renew Before Expiry** (default 30 days);
- the configured names changed;
- or none has been issued yet.

If a renewal fails, it's retried at the next check, and the error is shown on the page and written to the log.

## Setup

1. Choose a **Certificate Authority**. Start with **Let's Encrypt (staging)**. Its certificates aren't trusted by browsers, but it has much higher rate limits, so you can get the setup right first.
2. Read the CA's terms of service (linked on the page) and tick **I agree**. The server never agrees on your behalf.
3. Enter the **Domain Names**, one per line, for example `dns1.example.com`. Wildcards (`*.example.com`) are allowed. **Add Server Domain** inserts this server's own name.
4. Choose where the certificate is used: the web service, DNS-over-TLS/HTTPS/QUIC, or both.
   - **Enabling HTTPS:** when ACME manages the web certificate, you can enable HTTPS straight away, with **Enable HTTPS now** on this tab or on the Web Service tab. The certificate fields there show "Managed by ACME". Until the first certificate is issued, a temporary self-signed certificate is used, and the real one replaces it automatically.
   - **Encrypted DNS protocols:** enable DNS-over-TLS/HTTPS/QUIC on the Optional Protocols tab. They start as soon as the certificate is installed.
5. Choose and configure a **DNS-01 provider** (see below), then **Save ACME Settings**.
6. Click **Test DNS-01**. It publishes a test record, checks the public name servers can see it, and removes it, without contacting the CA.
7. Click **Request Certificate Now** and watch the log.
8. When a staging certificate is issued, switch the CA to **Let's Encrypt**, save, and request again.

## DNS-01 providers

### Zone on this DNS server

Use this when this server hosts the domain's zone as a **Primary zone** and is the zone's public name server, or feeds the public name servers by zone transfer. No credentials are needed.

On a **Cluster secondary node** the zone is a Secondary zone and can't be written. Use **RFC 2136** there, pointed at the Primary node.

### RFC 2136 dynamic update (TSIG)

Use this with any DNS server that accepts dynamic updates: BIND, PowerDNS, Knot, Windows DNS, another Technitium server (including the Cluster Primary), or a DNS host that supports RFC 2136.

- **Update Server:** an IP address or host name, optionally with a port: `192.168.1.2`, `ns1.example.com:53` or `[2001:db8::1]:53`.
- **TSIG Key:** pick a key defined in **Settings > TSIG**. On the update server, allow that key to update the zone. On Technitium, that's the zone's options under Dynamic Updates.

The zone is detected automatically by asking the update server for the SOA record.

### Cloudflare

Use this when the domain's public DNS is at Cloudflare. Create an API token in the Cloudflare dashboard with **Zone > DNS > Edit** permission for the zone and paste it in. The token is stored on this server and never shown again; leave the field empty to keep the saved token.

### Delegating challenges with a CNAME

If the domain is hosted somewhere without a supported provider, or you don't want API credentials for the whole zone on this server, you can point just the challenge name at a zone this server controls:

1. Host a small zone on this server that is publicly reachable, for example `acme.example.com`, delegated with NS records from the parent zone.
2. At the domain's DNS host, create the CNAME `_acme-challenge.dns1.example.com` → `_acme-challenge.dns1.example.com.acme.example.com` (any name inside the delegated zone works).
3. Select **Zone on this DNS server**.

The server follows the CNAME and publishes the TXT record at the target. Certificate authorities follow CNAMEs during validation (RFC 8555 section 8.4).

## Cluster

Each node has its own name, so each node manages its own certificate. Select the node with the node selector at the top right of Settings. ACME settings and certificates aren't part of the Cluster config transfer.

## Other certificate authorities

| CA | Notes |
|---|---|
| Let's Encrypt | No account credentials needed |
| ZeroSSL | Requires **EAB** (External Account Binding) credentials from your ZeroSSL dashboard |
| Google Trust Services | Requires EAB credentials from Google Cloud |
| Custom | Any RFC 8555 directory URL, e.g. step-ca `https://ca.example.lan/acme/acme/directory`. The server must trust the CA's own TLS certificate. |

Changing the CA creates a new account for that CA.

## Troubleshooting

The log at the bottom of the tab shows each step. Common problems:

| Message | Cause |
|---|---|
| `TXT record ... is visible on only 0 of N responding authoritative server(s)` | The record went into a zone the internet doesn't see, for example a local split-horizon copy of the zone. Publish to the public zone, use CNAME delegation, or increase **Propagation Timeout** for slow secondaries. |
| `No zone on this DNS server contains ...` | **Zone on this DNS server** was selected, but the server doesn't host the zone. |
| `... is a Secondary zone` | Use RFC 2136 to the zone's Primary server instead. |
| `RFC 2136 update ... was rejected: Refused / NotAuth` | The update server doesn't allow this TSIG key, or no key was selected. |
| `Cloudflare API request failed (403)` | The token lacks Zone > DNS > Edit for this zone. |
| `urn:ietf:params:acme:error:rateLimited` | You hit the CA's rate limit. Use the staging CA until the setup works. |

## Files

| File | Contents |
|---|---|
| `config/acme/acme.config` | Settings, the ACME account key and URL, provider credentials, and the certificate file password |
| `config/acme/certificate.pfx` | The current certificate, private key and chain |

Protect the config folder as you would the rest of the server's configuration.

## API

| Endpoint | Permission | Purpose |
|---|---|---|
| `/api/settings/acme/get` | Settings: View | Settings (secrets reported only as set or not set), status, current certificate, log |
| `/api/settings/acme/set` | Settings: Modify | `enabled`, `directoryUrl`, `termsOfServiceAgreed`, `email`, `eabKeyId`, `eabHmacKey`, `domains` (comma separated), `keyType` (`EcdsaP256`/`Rsa2048`), `useForWebService`, `useForDnsTls`, `dns01Provider` (`LocalZone`/`Rfc2136`/`Cloudflare`), `rfc2136Server`, `rfc2136TsigKeyName`, `cloudflareApiToken`, `renewDaysBeforeExpiry`, `propagationTimeoutSeconds`, `publicResolvers`. Empty secret parameters keep the saved values. |
| `/api/settings/acme/directoryInfo?directoryUrl=` | Settings: View | The CA's terms of service URL, and whether EAB is required |
| `/api/settings/acme/request` | Settings: Modify | Start issuing or renewing now (runs in the background; poll `get`) |
| `/api/settings/acme/testDns01` | Settings: Modify | Publish, verify and remove a test TXT record |
| `/api/settings/acme/enableHttps` | Settings: Modify | Enable HTTPS on the web service while ACME manages its certificate, using a temporary self-signed certificate until the first one is issued |

All endpoints accept `node=` to target a specific Cluster node.

## Limitations

- **Backups don't include ACME.** Settings backups don't include `config/acme/`. After restoring a backup, set up ACME again; a new certificate is requested on the next check.
- **The local-zone provider can write to any Primary zone.** Any user with Settings: Modify permission can make it publish challenge TXT records in any Primary zone on this server, regardless of per-zone permissions. Settings: Modify is effectively administrator access already.
- **Settings are refused while a request is running.** Saving settings is refused until the run finishes, so the order and the certificate request always use the same names.

## Adding a DNS-01 provider

Implement `IDns01Provider` (`AddTxtRecordAsync`, `RemoveTxtRecordAsync`) in `DnsServerCore/Acme/Dns01Providers.cs`. Then add a value to `Dns01ProviderType`, create the provider in `AcmeManager.CreateProvider()`, add its settings, and add an option to the GUI.
