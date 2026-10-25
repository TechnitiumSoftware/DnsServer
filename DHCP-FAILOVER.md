# DHCP Failover (hot-standby)

DHCP Failover adds active/passive (hot-standby) DHCP between two Technitium DNS Servers. **No Cluster is needed.** The two servers can talk to each other directly using a URL and an API token. If both are already members of a Cluster, they can use the Cluster connection instead.

## How it works

- **Primary** serves DHCP clients and pushes every lease change (commit, release, decline, admin removal, reserved/dynamic conversion) to the standby within ~0.5 s.
- **Standby** keeps the same scopes bound but stays silent. It mirrors the primary's scopes (settings and leases) via a full snapshot on start, whenever the primary's scope settings hash changes, and every 5 minutes.
- When the standby cannot reach the primary for the **partner down delay** (default 30 s), it takes over. Leases it hands out are capped at the **max client lead time** (default 1800 s). This keeps clients coming back quickly and limits the conflict window if the primary was actually alive (split brain).
- When the primary comes back, it first merges the standby's leases (the lease that expires later wins) and then serves again. The standby pushes all of its leases to the primary, hands back control and re-mirrors.

Clients don't need anything special. A client renewing at T1 unicasts to the server that issued its lease. If that server is down, the client broadcasts a rebind at T2, which the standby answers from its replicated lease table.

### States

| State | Primary serves? | Standby serves? |
|---|---|---|
| Startup | no (until first heartbeat result, ≤10 s) | no |
| Recovering | no (merging standby leases) | — |
| Normal | yes | no |
| CommunicationsInterrupted | yes | no (counting down to PartnerDown) |
| PartnerDown | — | yes (short leases) |
| Disabled | standalone DHCP | standalone DHCP |

## Setup (direct, no Cluster)

1. Put both servers on the same network segment as the DHCP clients. If you use a DHCP relay, point it at both servers' IPs.
2. On **each** server, create an API token for the other one to use: Administration > Sessions > Create Token, for a user in the **Administrators** group. Using a dedicated user such as `dhcp-failover` makes the token easy to recognize and revoke.
3. On the server that should normally serve DHCP, open DHCP > Failover and set:
   - **Enable DHCP Failover**: on
   - **Role**: Primary
   - **Connect To Partner**: Directly
   - **Partner URL**: the other server's web console, for example `https://dns2.home.lan:53443/`
   - **Partner API Token**: the token you created on the other server
   - **Ignore Partner Certificate Errors**: on, if the other server uses the default self-signed certificate
4. On the other server, do the same with **Role: Standby**, pointing back at the first server.
5. The status at the top of the tab should show both servers in **Normal** within a few seconds: Primary serving, Standby passive.

Plain `http://…:5380/` URLs work for servers without HTTPS enabled, but then the API token crosses your network unencrypted. Use HTTPS if you can.

The same settings are available through the API:

```
/api/dhcp/failover/set?token=...&enabled=true&role=Primary&partnerMode=Direct&partnerUrl=https://dns2.home.lan:53443/&partnerApiToken=<token from dns2>&partnerIgnoreCertificateErrors=true
```

If you leave `partnerApiToken` empty, the saved token is kept. `/api/dhcp/failover/get` never returns the token itself, only whether one is saved (`partnerApiTokenSet`).

## Setup (using an existing Cluster)

If both servers are already members of the same Cluster, choose **Connect To Partner: Using the Cluster** and pick the partner node. The servers then authenticate with the Cluster's own token, so you don't have to create one. API equivalent: `partnerMode=Cluster&partnerNodeName=<node name>`.

## Common settings

Optional parameters for `set`:

| Parameter | Default | Notes |
|---|---|---|
| `heartbeatIntervalSeconds` | 5 | |
| `partnerDownDelaySeconds` | 30 | Must be at least 2× the heartbeat interval. |
| `maxClientLeadTimeSeconds` | 1800 | |

Make all scope and lease changes on the **primary**. The standby rejects DHCP scope and lease edits while failover is enabled.

## API

| Endpoint | Permission | Purpose |
|---|---|---|
| `/api/dhcp/failover/get` | DhcpServer: View | Settings, local state, partner state |
| `/api/dhcp/failover/set` | DhcpServer: Modify | Update settings |
| `/api/admin/cluster/dhcp/status` | Administration: Delete | Server-to-server heartbeat |
| `/api/admin/cluster/dhcp/snapshot` | Administration: Delete | Binary scope + lease snapshot |
| `/api/admin/cluster/dhcp/leaseUpdates` (POST) | Administration: Delete | Binary incremental lease updates |

The server-to-server endpoints keep their `/cluster/` path for compatibility, but they work without a Cluster. They need a token with Administration permissions, which is why the partner token must belong to an administrator.

## Limitations / notes

- There are exactly two servers per failover pair.
- Settings, including the partner's API token, are stored in `dhcp-failover.config` in each server's config folder. Protect that folder like the rest of the server's config. They aren't part of the Cluster config transfer, because the role is different on each node.
- DHCP DNS updates go into each node's own local primary zone (the default behavior). If the scope's domain zone is a **cluster catalog member** (and so a secondary zone on the standby), DNS updates on the standby fail and are logged. Keep the DHCP domain zone out of the cluster catalog.
- If the partner answers at all, even with an error such as a rejected API token or failover turned off, the standby treats it as alive and never takes over. A wrong or revoked token therefore stops replication and logs a warning, but it won't start a second DHCP server.
- In Cluster mode, if the cluster is deleted or the partner node is removed from it, the standby can no longer find its partner and takes over after the delay. Disable failover first.
- Settings and live status are in the web console under DHCP > Failover. In a Cluster, pick the node in the node selector at the top right.
