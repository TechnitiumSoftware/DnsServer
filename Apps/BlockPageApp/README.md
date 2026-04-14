# Block Page App

A DNS App for Technitium DNS Server that serves a configurable block page from an embedded web server.

## Overview

- **Embedded web server** – serves a local page to users trying to access blocked domains
- **Multiple instances** – supports one or more named web server configurations
- **TLS support** – self-signed or custom PKCS#12 certificates
- **Dynamic or static mode** – generate a page or serve files from a web root

## Integration / extension points

- Implements: `IDnsApplication`
- Runs a built-in ASP.NET Core web server alongside DNS blocking.

## Configuration

`dnsApp.config` can be either a single object or an array of objects. Each object supports:

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | `default` | Instance name. |
| `enableWebServer` | boolean | `true` | Enables the web server instance. |
| `webServerLocalAddresses` | string[] | `[]` | Local IPs to bind to. |
| `webServerUseSelfSignedTlsCertificate` | boolean | `true` | Use a generated self-signed certificate. |
| `webServerTlsCertificateFilePath` | string | `null` | Path to a `.pfx`/`.p12` certificate. |
| `webServerTlsCertificatePassword` | string | `null` | Certificate password. |
| `webServerRootPath` | string | `wwwroot` | Static file root. |
| `serveBlockPageFromWebServerRoot` | boolean | `false` | Serve static files instead of generated block page. |
| `blockPageTitle` | string | `Website Blocked` | Page title. |
| `blockPageHeading` | string | `Website Blocked` | Page heading. |
| `blockPageMessage` | string | `This website has been blocked by your network administrator.` | Page message. |
| `includeBlockingInfo` | boolean | `true` | Include blocking info/EDE details on page. |

### Example

```json
[
  {
    "name": "default",
    "enableWebServer": true,
    "webServerLocalAddresses": ["0.0.0.0", "::"],
    "webServerUseSelfSignedTlsCertificate": true,
    "webServerTlsCertificateFilePath": null,
    "webServerTlsCertificatePassword": null,
    "webServerRootPath": "wwwroot",
    "serveBlockPageFromWebServerRoot": false,
    "blockPageTitle": "Website Blocked",
    "blockPageHeading": "Website Blocked",
    "blockPageMessage": "This website has been blocked by your network administrator.",
    "includeBlockingInfo": true
  }
]
```

## Runtime behavior

1. The app starts one or more embedded web servers.
2. If `serveBlockPageFromWebServerRoot` is `false`, it generates a page from the title/heading/message values.
3. If `serveBlockPageFromWebServerRoot` is `true`, it serves static content from `webServerRootPath`.
4. HTTPS can use a self-signed certificate or a custom PKCS#12 certificate.

## Risks / operational notes

- Browsers will warn on self-signed certificates.
- This app does not block queries by itself; DNS blocking must still be configured separately.
- Ensure the IPs in `webServerLocalAddresses` match the DNS blocking target addresses.

## Troubleshooting

- Confirm the web server binds to the expected IP/port.
- Confirm DNS blocking points clients to the web server IP.
- Verify the certificate path and password if using a custom certificate.
