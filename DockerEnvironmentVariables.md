# Technitium DNS Server Docker Environment Variables

Technitium DNS Server supports environment variables to allow initializing the config when the DNS server starts for the first time. These environment variables are useful for creating docker container and can be used as shown in the [docker-compose.yml](https://github.com/TechnitiumSoftware/DnsServer/blob/master/docker-compose.yml) file.

NOTE! These environment variables are read by the DNS server only when the DNS config file does not exists i.e. when the DNS server starts for the first time.

The environment variables are described below:

| Environment Variable                           | Type    | Description                                                                                                                              |
| ---------------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------  |
| DNS_SERVER_DOMAIN                              | String  | The primary domain name used by this DNS Server to identify itself.                                                                      |
| DNS_SERVER_ADMIN_PASSWORD                      | String  | The DNS web console admin user password.                                                                                                 |
| DNS_SERVER_ADMIN_PASSWORD_FILE                 | String  | The path to a file that contains a plain text password for the DNS web console admin user.                                               |
| DNS_SERVER_PREFER_IPV6                         | Boolean | DNS Server will use IPv6 for querying whenever possible with this option enabled.                                                        |
| DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES         | String  | A comma separated list of IP addresses for the DNS web console to listen on.                                                             |
| DNS_SERVER_WEB_SERVICE_HTTP_PORT               | Integer | The TCP port number for the DNS web console over HTTP protocol.                                                                          |
| DNS_SERVER_WEB_SERVICE_HTTPS_PORT              | Integer | The TCP port number for the DNS web console over HTTPS protocol.                                                                         |
| DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS            | Boolean | Enables HTTPS for the DNS web console.                                                                                                   |
| DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT    | Boolean | Enables self signed TLS certificate for the DNS web console.                                                                             |
| DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH    | String  | The file path to the TLS certificate for the DNS web console.                                                                            |
| DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PASSWORD| String  | The password for the TLS certificate for the DNS web console.                                                                            |
| DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT    | Boolean | Enables HTTP to HTTPS redirection for the DNS web console.                                                                               |
| DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP     | Boolean | Enables DNS server optional protocol DNS-over-HTTP on TCP port 80 to be used with a TLS terminating reverse proxy like nginx.            |
| DNS_SERVER_RECURSION                           | String  | Recursion options: `Allow`, `Deny`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworkACL`.                                             |
| DNS_SERVER_RECURSION_NETWORK_ACL               | String  | A comma separated list of IP addresses or network addresses to allow access. Add ! character at the start to deny access, e.g. !192.168.10.0/24 will deny entire subnet. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all except loopback. Valid only for `UseSpecifiedNetworkACL` recursion option. |
| DNS_SERVER_RECURSION_DENIED_NETWORKS           | String  | A comma separated list of IP addresses or network addresses to deny recursion. Valid only for `UseSpecifiedNetworkACL` recursion option. This option is obsolete and DNS_SERVER_RECURSION_NETWORK_ACL should be used instead.  |
| DNS_SERVER_RECURSION_ALLOWED_NETWORKS          | String  | A comma separated list of IP addresses or network addresses to allow recursion. Valid only for `UseSpecifiedNetworkACL` recursion option. This option is obsolete and DNS_SERVER_RECURSION_NETWORK_ACL should be used instead. |
| DNS_SERVER_ENABLE_BLOCKING                     | Boolean | Sets the DNS server to block domain names using Blocked Zone and Block List Zone.                                                        |
| DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT           | Boolean | Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests.                    |
| DNS_SERVER_BLOCK_LIST_URLS                     | String  | A comma separated list of block list URLs.                                                                                               |
| DNS_SERVER_FORWARDERS                          | String  | A comma separated list of forwarder addresses.                                                                                           |
| DNS_SERVER_FORWARDER_PROTOCOL                  | String  | Forwarder protocol options: `Udp`, `Tcp`, `Tls`, `Https`, `HttpsJson`.                                                                   |
| DNS_SERVER_LOG_USING_LOCAL_TIME                | Boolean | Enable this option to use local time instead of UTC for logging.                                                                         |

## Single Sign-On (SSO) Environment Variables

The following environment variables configure OpenID Connect (OIDC) Single Sign-On for the DNS Server web console:

| Environment Variable                     | Type    | Description                                                                                                                              |
| ---------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------  |
| DNS_SERVER_SSO_AUTHORITY                 | String  | The OIDC authority/issuer URL (e.g., `https://login.microsoftonline.com/{tenant-id}/v2.0`).                                              |
| DNS_SERVER_SSO_AUTHORITY_FILE            | String  | Path to file containing the OIDC authority URL.                                                                                          |
| DNS_SERVER_SSO_CLIENT_ID                 | String  | The OIDC client ID for the DNS Server application.                                                                                       |
| DNS_SERVER_SSO_CLIENT_ID_FILE            | String  | Path to file containing the OIDC client ID.                                                                                              |
| DNS_SERVER_SSO_CLIENT_SECRET             | String  | The OIDC client secret for the DNS Server application.                                                                                   |
| DNS_SERVER_SSO_CLIENT_SECRET_FILE        | String  | Path to file containing the OIDC client secret (recommended for secrets).                                                                |
| DNS_SERVER_SSO_SCOPES                    | String  | Space-separated OIDC scopes to request. Default: `openid profile email`.                                                                 |
| DNS_SERVER_SSO_SCOPES_FILE               | String  | Path to file containing OIDC scopes.                                                                                                     |
| DNS_SERVER_SSO_REDIRECT_URI            | String  | The OIDC redirect URI (overrides auto-detection).                                                                                        |
| DNS_SERVER_SSO_REDIRECT_URI_FILE       | String  | Path to file containing the OIDC redirect URI.                                                                                           |
| DNS_SERVER_SSO_METADATA_ADDRESS          | String  | The OIDC metadata endpoint URL (optional, auto-discovered if not set).                                                                   |
| DNS_SERVER_SSO_METADATA_ADDRESS_FILE     | String  | Path to file containing the OIDC metadata endpoint URL.                                                                                  |
| DNS_SERVER_SSO_ALLOW_HTTP                | Boolean | Allow OIDC metadata over HTTP. **INSECURE** - only use behind TLS-terminating reverse proxy. Default: `false`.                           |
| DNS_SERVER_SSO_ALLOW_SIGNUP              | Boolean | Allow automatic provisioning of new users via SSO. Default: `false`.                                                                     |
| DNS_SERVER_SSO_DEFAULT_GROUP             | String  | Default group name to assign all auto-provisioned SSO users. Leave empty for no default group.                                           |
| DNS_SERVER_SSO_DEFAULT_GROUP_FILE        | String  | Path to file containing the default group name.                                                                                          |
| DNS_SERVER_SSO_GROUP_MAPPINGS            | String  | JSON mapping of OIDC group GUIDs/claims to DNS Server groups (e.g., `{"oidc-group-guid": "Admins"}`).                                    |
| DNS_SERVER_SSO_GROUP_MAPPINGS_FILE       | String  | Path to file containing JSON group mappings.                                                                                             |
| DNS_SERVER_SSO_VERBOSE_LOGGING           | Boolean | Enable verbose logging of OIDC claims and SSO flow (for debugging). Default: `false`.                                                    |
| DNS_SERVER_SSO_MAX_AUTO_PROVISION        | Integer | Maximum number of users that can be auto-provisioned via SSO. Default: `25`. Set to `0` for unlimited.                                   |
| DNS_SERVER_SSO_PROVISIONING_RATE_LIMIT   | Integer | Maximum SSO auto-provisioning attempts per IP address per hour. Default: `25`. Set to `0` for unlimited.                                  |

**SSO Notes:**
- The `_FILE` variants allow reading sensitive values from files (Docker secrets pattern)
- Environment variables take precedence over web console configuration
- When environment variables are set, corresponding UI fields become read-only
- Clear Authority and Client ID in the web console to disable SSO

## Example SSO Configurations

### Microsoft Entra ID (Azure AD)

```bash
DNS_SERVER_SSO_AUTHORITY=https://login.microsoftonline.com/{tenant-id}/v2.0
DNS_SERVER_SSO_CLIENT_ID=your-application-client-id
DNS_SERVER_SSO_CLIENT_SECRET_FILE=/run/secrets/sso_client_secret
DNS_SERVER_SSO_SCOPES=openid profile email
DNS_SERVER_SSO_ALLOW_SIGNUP=true
DNS_SERVER_SSO_DEFAULT_GROUP=Administrators
DNS_SERVER_SSO_GROUP_MAPPINGS='{"group-object-id-1":"Administrators","group-object-id-2":"DNS Administrators"}'
DNS_SERVER_SSO_VERBOSE_LOGGING=false
```

**Note**: Replace `{tenant-id}` with your Azure AD tenant ID. Group GUIDs can be found in Azure Portal under Azure AD > Groups.

### Generic OIDC Provider

```bash
DNS_SERVER_SSO_AUTHORITY=https://your-oidc-provider.com/
DNS_SERVER_SSO_CLIENT_ID=your-client-id
DNS_SERVER_SSO_CLIENT_SECRET_FILE=/run/secrets/sso_client_secret
DNS_SERVER_SSO_METADATA_ADDRESS=https://your-oidc-provider.com/.well-known/openid-configuration
DNS_SERVER_SSO_SCOPES=openid profile email
DNS_SERVER_SSO_CALLBACK_PATH=/oidc/callback
DNS_SERVER_SSO_ALLOW_SIGNUP=false
DNS_SERVER_SSO_ALLOW_HTTP=false
```
