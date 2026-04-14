# Failover App

A DNS App for Technitium DNS Server that provides automated failover functionality based on continuous health monitoring of backend resources. The app monitors configured endpoints and dynamically returns DNS responses based on their availability status, enabling high-availability DNS architectures with zero manual intervention.

## Overview

The **Failover App** extends Technitium DNS Server with advanced health monitoring and failover capabilities for **A**, **AAAA**, and **CNAME** records in primary and forwarder zones. It continuously monitors backend servers using configurable health checks (ICMP ping, TCP connection, HTTP/HTTPS requests) and automatically adjusts DNS responses when failures are detected.

Key capabilities include:

- **Active health monitoring** with customizable intervals, timeouts, and retry logic
- **Multi-protocol health checks**: ICMP ping, TCP port probing, HTTP/HTTPS endpoint validation
- **Primary/secondary failover** logic for high-availability configurations
- **Real-time alerting** via email and webhooks when health status changes
- **Maintenance mode** to temporarily remove endpoints from rotation without disabling them
- **TXT record status queries** for operational visibility into health states

This app is essential for system administrators operating mission-critical DNS infrastructure requiring automated fault tolerance.

## ⚠️ Important Warning: APP Record vs. Native DNS Records

**The Failover App operates exclusively through APP records. It does NOT modify or interact with native A, AAAA, or CNAME records.**

**Critical operational considerations:**

- **Option A (Recommended)**: Use APP records exclusively in zones managed by this app
- **Option B (Discouraged)**: If mixing APP records with native records, ensure they target different FQDNs to prevent resolution conflicts

**Processing order implications:**

1. Native DNS records (A/AAAA/CNAME) are always evaluated first by the DNS server
2. APP records are only processed if no matching native record exists
3. Overlapping configurations will cause APP records to be ignored silently

**Example of conflicting configuration:**

```bind
example.com.  300  IN  A       192.0.2.1        ← This will always be returned
example.com.  APP  failover   (primary: 192.0.2.1, secondary: 192.0.2.2)  ← This will never be used
```

**Correct configuration approach:**

```bind
app.example.com.  APP  failover   (primary: 192.0.2.1, secondary: 192.0.2.2)
```

## Installation

1. Open the **Technitium DNS Server web console**
2. Navigate to **Apps** → **DNS Apps**
3. Click **Install** or **Update** to deploy the Failover App
4. Configure health checks, email alerts, and webhooks in `dnsApp.config`
5. Create APP records in your zones referencing the configured health checks

## Configuration

Configuration is managed through the `dnsApp.config` JSON file located in the app directory. The file defines health checks, notification mechanisms, and maintenance windows.

The configuration structure comprises four root-level arrays defining operational components.

### Root Configuration Options

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `healthChecks` | Array | `[]` | Defines available health check profiles with monitoring parameters |
| `emailAlerts` | Array | `[]` | Configures SMTP-based email notification profiles |
| `webHooks` | Array | `[]` | Defines HTTP webhook endpoints for status change notifications |
| `underMaintenance` | Array | `[]` | Specifies network ranges considered under maintenance (always returns FAILED status) |

### Health Check Configuration

Health checks define how backend resources are monitored. Each health check profile can be referenced by name in APP record configurations.

**Common Properties (All Types):**

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | `"default"` | Unique identifier for this health check profile |
| `type` | String | Required | Health check method: `ping`, `tcp`, `http`, `https` |
| `interval` | Integer | `60` | Time between health checks in seconds |
| `retries` | Integer | `3` | Number of consecutive failures before marking unhealthy |
| `timeout` | Integer | `10` | Maximum time in seconds to wait for response |
| `emailAlert` | String | `null` | Name of email alert profile to use (or `"default"`) |
| `webHook` | String | `null` | Name of webhook profile to use (or `"default"`) |

**Type-Specific Properties:**

| Property | Type | Applies To | Description |
| --- | --- | --- | --- |
| `port` | Integer | `tcp` | TCP port number to test connectivity |
| `url` | String/null | `http`, `https` | Full URL to request; if `null`, URL is derived from domain name |

**Example Health Check Configurations:**

```json
{
  "name": "ping",
  "type": "ping",
  "interval": 60,
  "retries": 3,
  "timeout": 10,
  "emailAlert": "default",
  "webHook": "default"
}
```

```json
{
  "name": "tcp443",
  "type": "tcp",
  "interval": 60,
  "retries": 3,
  "timeout": 10,
  "port": 443,
  "emailAlert": "default",
  "webHook": "default"
}
```

```json
{
  "name": "https",
  "type": "https",
  "interval": 60,
  "retries": 3,
  "timeout": 10,
  "url": null,
  "emailAlert": "default",
  "webHook": "default"
}
```

### Email Alert Configuration

Email alerts send notifications when monitored endpoints transition between health states.

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | `"default"` | Unique identifier for this alert profile |
| `enabled` | Boolean | `false` | Whether email alerts are active |
| `alertTo` | Array of Strings | `[]` | Recipient email addresses |
| `smtpServer` | String | Required | SMTP server hostname or IP address |
| `smtpPort` | Integer | `465` | SMTP server port (25, 465, 587 typical) |
| `startTls` | Boolean | `false` | Use STARTTLS upgrade on plaintext connection |
| `smtpOverTls` | Boolean | `true` | Use implicit TLS from connection start |
| `username` | String | Required | SMTP authentication username |
| `password` | String | Required | SMTP authentication password |
| `mailFrom` | String | Required | Sender email address |
| `mailFromName` | String | `"DNS Server Alert"` | Sender display name |

**Example:**

```json
{
  "name": "default",
  "enabled": true,
  "alertTo": ["admin@example.com", "ops@example.com"],
  "smtpServer": "smtp.gmail.com",
  "smtpPort": 587,
  "startTls": true,
  "smtpOverTls": false,
  "username": "alerts@example.com",
  "password": "app-specific-password",
  "mailFrom": "alerts@example.com",
  "mailFromName": "DNS Failover System"
}
```

### Webhook Configuration

Webhooks send HTTP POST requests with JSON payloads when health status changes.

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | String | `"default"` | Unique identifier for this webhook profile |
| `enabled` | Boolean | `false` | Whether webhook notifications are active |
| `urls` | Array of Strings | `[]` | HTTP/HTTPS endpoints to receive POST notifications |

**Webhook Payload Structure:**

```json
{
  "timestamp": "2026-01-26T12:34:56Z",
  "address": "192.0.2.1",
  "domain": "app.example.com",
  "type": "A",
  "healthCheck": "https",
  "previousStatus": "Healthy",
  "currentStatus": "Failed",
  "failureReason": "Connection timeout after 10000ms"
}
```

**Example:**

```json
{
  "name": "default",
  "enabled": true,
  "urls": [
    "https://monitoring.example.com/webhooks/dns-failover",
    "https://slack.com/api/webhooks/T00000000/B00000000/XXXXXXXXXXXX"
  ]
}
```

### Maintenance Mode Configuration

Networks in maintenance mode always return `FAILED` health status, effectively removing them from rotation without deleting configurations.

| Property | Type | Description |
| --- | --- | --- |
| `network` | String | Network address in CIDR notation (e.g., `192.168.1.0/24` or `192.168.1.1/32`) |
| `enabled` | Boolean | Whether this maintenance rule is active |

**Example:**

```json
{
  "network": "192.168.10.2/32",
  "enabled": true
}
```

## APP Record Configuration

APP records are created in DNS zones and reference health check profiles. The app supports two record types:

### Address-Based Failover (A/AAAA Records)

Returns IP addresses based on health status with primary/secondary failover logic.

**JSON Structure:**

```json
{
  "primary": {
    "addresses": ["192.0.2.1", "192.0.2.2"]
  },
  "secondary": {
    "addresses": ["198.51.100.1", "198.51.100.2"]
  },
  "healthCheck": "https",
  "healthCheckUrl": "https://app.example.com/health"
}
```

**Properties:**

| Property | Type | Description |
| --- | --- | --- |
| `primary.addresses` | Array of Strings | Primary IP addresses (IPv4/IPv6) to return when healthy |
| `secondary.addresses` | Array of Strings | Fallback IP addresses returned when all primary addresses fail |
| `healthCheck` | String | Name of health check profile to use |
| `healthCheckUrl` | String (optional) | Override URL for HTTP/HTTPS checks; if omitted, defaults to `https://<queried-domain>` |

### CNAME-Based Failover

Returns domain names based on health status.

**JSON Structure:**

```json
{
  "primary": {
    "domain": "server1.example.com"
  },
  "secondary": {
    "domain": "server2.example.com"
  },
  "healthCheck": "tcp443",
  "healthCheckUrl": "https://server1.example.com/status"
}
```

**Properties:**

| Property | Type | Description |
| -------- | ---- | ----------- |
| `primary.domain` | String | Primary domain name to return when healthy |
| `secondary.domain` | String | Fallback domain name when primary fails |
| `healthCheck` | String | Name of health check profile to use |
| `healthCheckUrl` | String (optional) | Override URL for health validation |

**Special Behavior for Zone Apex:**

When the queried name equals the zone apex, the app returns **ANAME** records instead of CNAME (which is prohibited at zone apex per RFC specifications).

## Example Configuration

Complete `dnsApp.config` demonstrating all features:

```json
{
  "healthChecks": [
    {
      "name": "ping",
      "type": "ping",
      "interval": 30,
      "retries": 3,
      "timeout": 5,
      "emailAlert": "critical",
      "webHook": "slack"
    },
    {
      "name": "web-service",
      "type": "https",
      "interval": 60,
      "retries": 2,
      "timeout": 15,
      "url": null,
      "emailAlert": "critical",
      "webHook": "slack"
    },
    {
      "name": "database",
      "type": "tcp",
      "interval": 45,
      "retries": 3,
      "timeout": 10,
      "port": 5432,
      "emailAlert": "ops",
      "webHook": "pagerduty"
    }
  ],
  "emailAlerts": [
    {
      "name": "critical",
      "enabled": true,
      "alertTo": ["oncall@example.com"],
      "smtpServer": "smtp.gmail.com",
      "smtpPort": 587,
      "startTls": true,
      "smtpOverTls": false,
      "username": "dns-alerts@example.com",
      "password": "secure-app-password",
      "mailFrom": "dns-alerts@example.com",
      "mailFromName": "DNS Failover Monitor"
    },
    {
      "name": "ops",
      "enabled": true,
      "alertTo": ["ops-team@example.com"],
      "smtpServer": "smtp.office365.com",
      "smtpPort": 587,
      "startTls": true,
      "smtpOverTls": false,
      "username": "monitoring@example.com",
      "password": "another-password",
      "mailFrom": "monitoring@example.com",
      "mailFromName": "Infrastructure Monitor"
    }
  ],
  "webHooks": [
    {
      "name": "slack",
      "enabled": true,
      "urls": ["https://hooks.slack.com/services/T00/B00/XXXX"]
    },
    {
      "name": "pagerduty",
      "enabled": true,
      "urls": ["https://events.pagerduty.com/v2/enqueue"]
    }
  ],
  "underMaintenance": [
    {
      "network": "192.168.99.0/24",
      "enabled": false
    }
  ]
}
```

**Corresponding APP Record (Address Type):**

```json
{
  "primary": {
    "addresses": [
      "203.0.113.10",
      "203.0.113.11"
    ]
  },
  "secondary": {
    "addresses": [
      "198.51.100.50",
      "198.51.100.51"
    ]
  },
  "healthCheck": "web-service"
}
```

## How Failover Works

The app implements a continuous monitoring and evaluation pipeline:

1. **Health Check Initialization**: On startup, the app parses `dnsApp.config` and initializes health check timers based on configured intervals.

2. **Periodic Monitoring**: Each health check executes on its configured interval:
   - **Ping**: ICMP Echo Request/Reply
   - **TCP**: Socket connection to specified port
   - **HTTP/HTTPS**: HTTP GET request expecting 2xx/3xx status codes

3. **Status Evaluation**: Health check results are classified:
   - **Unknown**: First check or insufficient data (initial state)
   - **Healthy**: Check succeeded within timeout
   - **Failed**: Check failed `retries` consecutive times
   - **Maintenance**: IP address matches an enabled maintenance network

4. **DNS Query Processing**: When a query arrives for an APP record:
   - Parse APP record JSON data
   - Retrieve current health status for primary addresses/domains
   - If all primary resources are **Healthy** or **Unknown**, return primary addresses with configured TTL
   - If all primary resources are **Failed** or **Maintenance**, return secondary addresses
   - If primary is **Unknown**, return with reduced TTL (10 seconds) to enable rapid failover once status is determined

5. **State Change Notification**: When status transitions occur:
   - Log event to DNS server logs
   - Trigger configured email alerts
   - POST status change to configured webhooks

6. **Cache Expiration Management**: Health monitors expire after 1 hour of inactivity (no queries) to conserve resources.

## Use Cases

### High-Availability Web Service with Geographic Failover

Primary datacenter in US-East, secondary in EU-West. If primary becomes unreachable, DNS automatically directs traffic to secondary.

```json
{
  "primary": { "addresses": ["203.0.113.10"] },
  "secondary": { "addresses": ["198.51.100.20"] },
  "healthCheck": "https",
  "healthCheckUrl": "https://app.example.com/health"
}
```

### Multi-Homed DNS with CNAME Failover

Point `www.example.com` to a CDN provider; failover to origin server if CDN health check fails.

```json
{
  "primary": { "domain": "example.cdn.com" },
  "secondary": { "domain": "origin.example.com" },
  "healthCheck": "https"
}
```

### Database Read Replica Load Balancing

Monitor multiple read replicas; remove failed instances from rotation automatically.

```json
{
  "primary": {
    "addresses": [
      "10.0.1.10",
      "10.0.1.11",
      "10.0.1.12"
    ]
  },
  "secondary": {
    "addresses": ["10.0.2.100"]
  },
  "healthCheck": "database"
}
```

### Maintenance Window Handling

Temporarily remove a server from DNS rotation without deleting its configuration.

```json
{
  "network": "203.0.113.10/32",
  "enabled": true
}
```

### Active-Passive Cluster with Email Alerts

Monitor active server; automatically failover to passive and alert operations team.

```json
{
  "primary": { "addresses": ["192.0.2.10"] },
  "secondary": { "addresses": ["192.0.2.20"] },
  "healthCheck": "tcp443"
}
```

Health check configuration:

```json
{
  "name": "tcp443",
  "type": "tcp",
  "port": 443,
  "interval": 30,
  "retries": 2,
  "timeout": 5,
  "emailAlert": "critical",
  "webHook": "slack"
}
```

### Multi-Protocol Health Validation

Use different health checks for different service layers (ping for network, TCP for service, HTTPS for application).

## Troubleshooting

### Health Checks Always Show "Unknown" Status

**Symptoms**: DNS queries return addresses with 10-second TTL; logs show no health check activity.

**Diagnostic Steps**:

1. Verify health check configuration syntax in `dnsApp.config`
2. Check DNS server logs for initialization errors:

   ```bash
   Apps → View Logs
   ```

3. Ensure health check name in APP record matches exactly (case-sensitive)
4. Verify `interval` is not set to an excessively large value

**Resolution**:

- Correct health check name reference
- Reload app configuration via web console
- Wait one health check interval for first status update

### Email Alerts Not Sending

**Symptoms**: Status changes occur but no emails received.

**Diagnostic Steps**:

1. Check `enabled: true` in email alert configuration
2. Verify SMTP credentials and server connectivity:

   ```bash
   telnet smtp.example.com 587
   ```

3. Review DNS server logs for SMTP errors
4. Test SMTP settings using external tool (e.g., `swaks`)
5. Verify firewall permits outbound connections on SMTP port

**Resolution**:

- Confirm `startTls` and `smtpOverTls` settings match server requirements
- Use app-specific passwords for services like Gmail
- Check spam/junk folders for delivered messages

### Failover Not Occurring During Outage

**Symptoms**: Primary server is down but DNS still returns primary addresses.

**Diagnostic Steps**:

1. Query TXT record for status visibility:

   ```bash
   dig @dns-server example.com TXT
   ```

2. Check health check `retries` value—must exceed consecutive failures
3. Verify health check type matches service (e.g., don't use `ping` if ICMP is blocked)
4. Confirm `timeout` is sufficient for network latency
5. Check if address is in `underMaintenance` with `enabled: true`

**Resolution**:

- Reduce `retries` for faster failover detection
- Increase `timeout` for high-latency environments
- Use HTTP/HTTPS health checks for application-layer validation
- Disable maintenance mode if unintentionally enabled

### Webhook Notifications Failing

**Symptoms**: Status changes logged but webhook endpoint receives no data.

**Diagnostic Steps**:

1. Verify webhook URL is reachable from DNS server:

   ```bash
   curl -X POST https://webhook.example.com/endpoint -d '{"test":"data"}'
   ```

2. Check DNS server logs for HTTP errors
3. Confirm webhook endpoint accepts `Content-Type: application/json`
4. Test with webhook inspection service (e.g., webhook.site)

**Resolution**:

- Ensure webhook URL is publicly accessible or server has route
- Verify endpoint authentication requirements (API keys, headers)
- Check if proxy configuration is required

### High TTL Preventing Failover

**Symptoms**: Failover occurs in logs but clients continue using failed servers.

**Cause**: Clients and recursive resolvers cache responses per original TTL.

**Resolution**:

- Reduce APP record TTL to 60-300 seconds for failover-critical services
- Understand health check initial state returns 10-second TTL by design
- Implement client-side timeouts and retries for critical applications

### App Not Loading or Initializing

**Symptoms**: App shows as installed but records return no data.

**Diagnostic Steps**:

1. Check DNS server logs for app initialization errors
2. Verify `dnsApp.config` is valid JSON:

   ```bash
   cat dnsApp.config | jq .
   ```

3. Ensure .NET 9.0 runtime is installed
4. Restart DNS server service

**Resolution**:

- Fix JSON syntax errors
- Reinstall app via web console
- Check file permissions on app directory
