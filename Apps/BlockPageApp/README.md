# Block Page App

A DNS App for Technitium DNS Server that serves a customizable block page from a built-in web server when DNS queries are blocked, providing end-user notification and transparency for DNS filtering operations.

## Overview

The **Block Page App** extends Technitium DNS Server functionality by operating an embedded ASP.NET Core web server that displays informational pages to users when their DNS requests are blocked. This application intercepts HTTP/HTTPS requests to blocked domains and presents a configurable notification page explaining the block action. The app supports multiple web server instances, self-signed and custom TLS certificates, and dynamic inclusion of Extended DNS Error (EDE) information from RFC 8914.

**Key capabilities:**

- **Built-in HTTP/HTTPS web server** for serving block pages on ports 80 and 443
- **Customizable block page content** including title, heading, and message
- **Automatic TLS certificate management** with self-signed certificate generation
- **Extended DNS Error (EDE) integration** displaying detailed blocking reasons
- **Multiple web server instances** with independent configurations
- **Static file serving** from custom web root directories

Administrative value: Provides transparency and accountability in DNS filtering deployments, reduces helpdesk burden by informing users of block reasons, and supports compliance requirements for content filtering visibility.

## ⚠️ Important Warning: DNS Server Configuration Required

This application does **not** automatically configure DNS blocking behavior. It only serves block pages when users attempt to access blocked domains via HTTP/HTTPS.

**Required DNS Server Configuration:**

To enable block page functionality, you **must** manually configure the Technitium DNS Server blocking settings:

1. Navigate to **Settings** → **Blocking** in the DNS Server web console
2. Set **Blocking Type** to **Custom Address**
3. Configure **Custom Blocking Addresses** to the IP address(es) where this app's web server is listening
   - Use the DNS server's own IP address(es)
   - Must match addresses configured in `webServerLocalAddresses`

**Processing Order:**

The DNS server blocks the query first → responds with custom IP address → client browser connects to custom IP address → this app's web server serves the block page.

**Certificate Warnings:**

When HTTPS is enabled (via self-signed or custom certificates), users will encounter browser certificate warnings. This is expected behavior. Users must manually accept the certificate exception to view the block page.

## Installation

1. Open the Technitium DNS Server web console in your browser
2. Navigate to **Apps** in the main menu
3. Click **Install** or **Update** and locate the BlockPageApp package
4. Configure the app using the `dnsApp.config` file or web console interface

## Configuration

The app is configured via the `dnsApp.config` JSON file located in the app installation directory. The configuration supports both single-object and array formats for managing multiple web server instances.

### Root Configuration Options

The configuration file accepts an **array of web server objects**. Each object represents an independent web server instance.

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | `"default"` | Unique identifier for the web server instance |
| `enableWebServer` | boolean | `true` | Enables or disables this web server instance |
| `webServerLocalAddresses` | string[] | `["0.0.0.0", "::"]` | IP addresses on which the web server listens (IPv4/IPv6) |
| `webServerUseSelfSignedTlsCertificate` | boolean | `true` | Automatically generates and uses a self-signed certificate for HTTPS |
| `webServerTlsCertificateFilePath` | string | `null` | Path to PKCS #12 certificate file (.pfx or .p12) for HTTPS |
| `webServerTlsCertificatePassword` | string | `null` | Password for the TLS certificate file (if password-protected) |
| `webServerRootPath` | string | `"wwwroot"` | Directory path for serving static files (relative or absolute) |
| `serveBlockPageFromWebServerRoot` | boolean | `false` | If `true`, serves files from `webServerRootPath`; if `false`, generates dynamic block page |
| `blockPageTitle` | string | `"Website Blocked"` | HTML page title displayed in browser tab |
| `blockPageHeading` | string | `"Website Blocked"` | Main heading (H1) displayed on block page |
| `blockPageMessage` | string | `"This website has been blocked by your network administrator."` | Descriptive message explaining the block |
| `includeBlockingInfo` | boolean | `true` | Dynamically includes Extended DNS Error (EDE) information on the block page |

### TLS Certificate Configuration

The app supports three TLS certificate modes:

#### Option A: Self-Signed Certificate (Default)

```json
{
  "webServerUseSelfSignedTlsCertificate": true,
  "webServerTlsCertificateFilePath": null,
  "webServerTlsCertificatePassword": null
}
```

The app automatically generates a 5-year self-signed certificate stored as `self-signed-cert.pfx` in the app directory.

#### Option B: Custom Certificate

```json
{
  "webServerUseSelfSignedTlsCertificate": false,
  "webServerTlsCertificateFilePath": "/path/to/certificate.pfx",
  "webServerTlsCertificatePassword": "your-password"
}
```

Provide a PKCS #12 formatted certificate file (.pfx or .p12). The app monitors the file for changes and reloads certificates automatically every 60 seconds.

#### Option C: HTTP Only (No TLS)

```json
{
  "webServerUseSelfSignedTlsCertificate": false,
  "webServerTlsCertificateFilePath": null
}
```

Disables HTTPS entirely. The web server only listens on port 80.

### Static File Serving Mode

#### Dynamic Block Page (Default)

```json
{
  "serveBlockPageFromWebServerRoot": false,
  "blockPageTitle": "Access Denied",
  "blockPageHeading": "This Site Is Blocked",
  "blockPageMessage": "Contact your IT department for assistance."
}
```

The app generates an HTML block page dynamically using configured text values.

#### Static File Mode

```json
{
  "serveBlockPageFromWebServerRoot": true,
  "webServerRootPath": "/var/www/blockpage"
}
```

The app serves files directly from `webServerRootPath`. Place an `index.html` file in this directory. All requests are redirected to the root path. Static files (CSS, images, JavaScript) are served with `no-cache` headers.

### Multiple Web Server Instances

The configuration supports multiple independent web server instances:

```json
[
  {
    "name": "internal-network",
    "enableWebServer": true,
    "webServerLocalAddresses": ["192.168.1.1"],
    "blockPageMessage": "This site is blocked per company policy."
  },
  {
    "name": "guest-network",
    "enableWebServer": true,
    "webServerLocalAddresses": ["10.0.0.1"],
    "blockPageMessage": "Guest network access is restricted."
  }
]
```

Each instance operates independently with unique configurations.

## Example Configuration

```json
[
  {
    "name": "default",
    "enableWebServer": true,
    "webServerLocalAddresses": [
      "0.0.0.0",
      "::"
    ],
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

## Supported TLS Certificate Formats

| Format | Extension | Description |
| --- | --- | --- |
| PKCS #12 | `.pfx` | Microsoft Personal Information Exchange format (binary) |
| PKCS #12 | `.p12` | PKCS #12 format with alternate extension |

### Requirements

- Certificate file must contain a certificate with a private key
- May contain additional intermediate certificates (certificate chain)
- Password protection is optional

## How Block Page Serving Works

The application processes HTTP/HTTPS requests using the following pipeline:

1. **DNS Query Interception**: The DNS server blocks a query and responds with a custom IP address (configured in DNS blocking settings)

2. **HTTP/HTTPS Request**: The user's browser attempts to connect to the blocked domain, which resolves to the custom IP address where this app is listening

3. **Request Handling**: The embedded web server receives the HTTP/HTTPS request on port 80 or 443

4. **Extended DNS Error Retrieval** (if `includeBlockingInfo` is `true`):
   - The app issues a direct DNS query to the DNS server for the requested hostname
   - Extracts Extended DNS Error (EDE) options from the EDNS section (RFC 8914)
   - Formats EDE information codes and extra text for display

5. **Page Generation**:
   - In dynamic mode: Generates HTML with configured title, heading, message, and blocking info
   - In static mode: Serves files from `webServerRootPath` with redirect to root

6. **Response**: Returns HTTP 200 with `Content-Type: text/html` and `X-Robots-Tag: noindex, nofollow` headers

7. **TLS Certificate Update**: If a custom certificate is configured, a background timer checks for file modifications every 60 seconds and reloads the certificate automatically

## Use Cases

1. **Corporate Content Filtering Transparency:** Deploy block pages in enterprise environments to inform employees which sites are blocked and provide policy references for acceptable use guidelines.
2. **ISP Compliance and Legal Notices:** Internet service providers can display legally required notifications when blocking access to court-ordered restricted content or malware distribution sites.
3. **Parental Control Feedback:** Home network administrators using DNS filtering for parental controls can configure child-friendly block messages explaining restricted content categories.
4. **Security Incident Reduction:** Display detailed EDE information to inform users when sites are blocked due to threat intelligence feeds, reducing false-positive reports to security teams.
5. **Multi-Tenant Network Segmentation:** Configure multiple web server instances with different block messages for separate network segments (guest, employee, contractor) with tailored messaging.
6. **Educational Institution Policy Enforcement:** Schools and universities can serve block pages that reference acceptable use policies and provide contact information for exceptions or appeals.

## Troubleshooting

### Block Page Not Displayed

**Symptoms**: Users receive browser errors (connection refused, timeout) instead of block page

**Resolution**:

1. Verify DNS server blocking settings: **Settings** → **Blocking** → **Blocking Type** must be **Custom Address**
2. Confirm **Custom Blocking Addresses** match `webServerLocalAddresses` in `dnsApp.config`
3. Check web server status in DNS Server logs:

   ```yaml
   Web server 'default' was bound successfully: 0.0.0.0:80
   Web server 'default' was bound successfully: 0.0.0.0:443
   ```

4. Verify firewall rules allow inbound connections on ports 80 and 443
5. Test web server accessibility: `curl http://<server-ip>` or `curl https://<server-ip>` (expect certificate warnings for HTTPS)

### HTTPS Certificate Warnings

**Symptoms**: Browser displays "Your connection is not private" or similar security warnings

**Expected Behavior**: Self-signed certificates and certificates with hostname mismatches will always produce warnings

**Resolution**:

1. This is normal behavior when using `webServerUseSelfSignedTlsCertificate: true`
2. Users must click "Advanced" and "Proceed" (or equivalent) to view block page
3. For production deployments, consider:
   - Option A: Use HTTP-only mode (`webServerUseSelfSignedTlsCertificate: false`, `webServerTlsCertificateFilePath: null`)
   - Option B: Deploy a valid wildcard certificate trusted by client browsers

### Missing Extended DNS Error Information

**Symptoms**: Block page displays but does not show detailed blocking reasons

**Diagnostic Steps**:

1. Verify `includeBlockingInfo: true` in configuration
2. Check that the blocking rule or list generates EDE information (Advanced Blocking, Allowed/Blocked zones)
3. Review DNS Server logs for DirectQuery errors
4. Test DNS query manually: `dig @<server-ip> <blocked-domain>` and verify EDNS EDE options in response

### Web Server Fails to Bind

**Symptoms**: Log entries show "Web server 'default' failed to bind"

**Resolution**:

1. Check if ports 80/443 are already in use:
   - Linux: `sudo netstat -tulpn | grep -E ':(80|443)'`
   - Windows: `netstat -ano | findstr ":80 :443"`
2. Verify `webServerLocalAddresses` contains valid local IP addresses
3. On Linux, binding to port 80/443 may require elevated privileges
4. Ensure no other web servers (Apache, Nginx, IIS) are using the same ports
5. Change `webServerLocalAddresses` to specific IP addresses instead of `0.0.0.0` to avoid conflicts

### Custom Certificate Not Loading

**Symptoms**: Web server uses self-signed certificate instead of custom certificate

**Diagnostic Steps**:

1. Verify `webServerTlsCertificateFilePath` points to an existing .pfx or .p12 file
2. Check file permissions allow DNS Server process to read the certificate file
3. Confirm certificate contains a private key: `openssl pkcs12 -in cert.pfx -info -noout` (enter password if required)
4. Review DNS Server logs for certificate loading errors:

   ```yaml
   Web server 'default' TLS certificate was loaded: /path/to/cert.pfx
   ```

5. Ensure `webServerUseSelfSignedTlsCertificate: false` when using custom certificates

## License

This app is part of Technitium DNS Server. This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. For more information, see the [LICENSE](https://github.com/TechnitiumSoftware/DnsServer/blob/master/LICENSE) file in the Technitium DNS Server repository.

Copyright (C) 2024 Shreyas Zare (<shreyas@technitium.com>)
