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
    "tags": [
        "autodiscovery"
    ],
    "cidr": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7"
    ]
}
```

- `type` - type of guests to autodiscover. Supported values are `qemu` for QEMU vms, `lxc` for LXCs and `null` for both.
- `tags` - list of tags. Only guests that have all tags in the list will be discovered.
- `cidr` - list of networks in CIDR notation. Server will return only addresses in these networks.

# Acknowledgement

Thanks to [Nikita Rukavkov](https://github.com/itcaat) and [Andrew Dunham](https://github.com/andrew-d) for the reference implementations.
