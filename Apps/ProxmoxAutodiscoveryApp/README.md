# Proxmox Autodiscovery for Technitium DNS Server

A plugin that allows query DNS server for ip addresses of Proxmox QEMUs and LXCs without needing to add A/AAAA records manually.

It collects QEMU and LXC data (name, tags and network addresses) form Proxmox API and periodically refreshes it.

## Features

- Stores Proxmox data in memory, dns resolution requires no additional network requests.
- Allows to filter autodiscovered guests based on tags and type.
- Filters guests network addresses based on list of allowed networks.
- Supports both IPv4 and IPv6.

## Dns App configuration

Supply a JSON configuration like the following:

```json
{
    "enabled": false,
    "proxmoxHost": "https://example.com:8006",
    "timeoutSeconds": 10,
    "disableSslValidation": false,
    "accessToken": "user@pve!token-name=token-secret",
    "updateIntervalSeconds": 60
}
```

- `enabled` - enables/disables APP.
- `proxmoxHost` - url of Proxmox API.
- `timeoutSeconds` - configurable timeout of HTTP calls to Proxmox API.
- `disableSslValidation` - disables SSL certificate validation of Proxmox API.
- `accessToken` - Proxmox API access token in specified format. Read-only permissions are enough.
- `updateIntervalSeconds` - how often app must query Proxmox API for new data.

## APP record configuration

Supply a JSON configuration like the following:

```json
{
  "type": "qemu",
  "tags": {
    "allowed": [
      "autodiscovery"
    ],
    "excluded": [
      "hidden"
    ]
  },
  "networks": {
    "allowed": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "fc00::/7"
    ],
    "excluded": [
    ]
  }
}
```

- `type` - type of guests to autodiscover. Supported values are `qemu` for QEMU vms, `lxc` for LXCs and `null` for both.
- `tags` - filter guests by tag list.
  - `allowed` - guest must have all specified tags to be discovered. Empty list means all guests are discoverable.
  - `excluded` - guest must have no tags from the list to be discovered. Empty list means no guests are excluded.
- `networks` - filter returned IP addresses by networks.
  - `allowed` - resolve only addresses belonging to any network from the list. Empty list means no IPs are discoverable.
  - `exluded` - resolve only addresses not belonging any networks from the list. Empty list means no IPs are excluded.

## Example

Discover all Proxmox guests:

```json
{
  "type": null,
  "tags": {
    "allowed": [],
    "excluded": []
  },
  "networks": {
    "allowed": [
      "0.0.0.0/0",
      "::/0"
    ],
    "excluded": [
    ]
  }
}
```

Discover only QEMUs with `test`, `provider` tags, excluding `broken`. Resolve only IPv4 addresses in private range excluding default docker bridge:

```json
{
  "type": "qemu",
  "tags": {
    "allowed": [
      "test",
      "provider"
    ],
    "excluded": [
      "broken"
    ]
  },
  "networks": {
    "allowed": [
      "172.16.0.0/12"
    ],
    "excluded": [
      "172.17.0.0/16"
    ]
  }
}
```

# Acknowledgement

Thanks to [Nikita Rukavkov](https://github.com/itcaat) and [Andrew Dunham](https://github.com/andrew-d) for the reference implementations.
