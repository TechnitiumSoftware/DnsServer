# Technitium DNS Server Docker Environment Variables

Technitium DNS Server supports environment variables to allow initializing the config when the DNS server starts for the first time. These environment variables are useful for creating docker container and can be used as shown in the [docker-compose.yml](https://github.com/TechnitiumSoftware/DnsServer/blob/master/docker-compose.yml) file.

NOTE! These environment variables are read by the DNS server only when the DNS config file does not exists i.e. when the DNS server starts for the first time.

The environment variables are described below:

| Environment Variable                              | Type    | Description                                                                                                                              |
| ------------------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------|
| DNS_SERVER_DOMAIN                                 | String  | The primary domain name used by this DNS Server to identify itself.                                                                      |
| DNS_SERVER_ADMIN_PASSWORD                         | String  | The DNS web console admin user password.                                                                                                 |
| DNS_SERVER_ADMIN_PASSWORD_FILE                    | String  | The path to a file that contains a plain text password for the DNS web console admin user.                                               |
| DNS_SERVER_PREFER_IPV6                            | Boolean | DNS Server will use IPv6 for querying whenever possible with this option enabled.                                                        |
| DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES            | String  | A comma separated list of IP addresses for the DNS web console to listen on.                                                             |
| DNS_SERVER_WEB_SERVICE_HTTP_PORT                  | Integer | The TCP port number for the DNS web console over HTTP protocol.                                                                          |
| DNS_SERVER_WEB_SERVICE_HTTPS_PORT                 | Integer | The TCP port number for the DNS web console over HTTPS protocol.                                                                         |
| DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS               | Boolean | Enables HTTPS for the DNS web console.                                                                                                   |
| DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT       | Boolean | Enables self signed TLS certificate for the DNS web console.                                                                             |
| DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH       | String  | The file path to the TLS certificate for the DNS web console.                                                                            |
| DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PASSWORD   | String  | The password for the TLS certificate for the DNS web console.                                                                            |
| DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT       | Boolean | Enables HTTP to HTTPS redirection for the DNS web console.                                                                               |
| DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP        | Boolean | Enables DNS server optional protocol DNS-over-HTTP on TCP port 80 to be used with a TLS terminating reverse proxy like nginx.            |
| DNS_SERVER_RECURSION                              | String  | Recursion options: `Allow`, `Deny`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworkACL`.                                             |
| DNS_SERVER_RECURSION_NETWORK_ACL                  | String  | A comma separated list of IP addresses or network addresses to allow access. Add ! character at the start to deny access, e.g. !192.168.10.0/24 will deny entire subnet. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all except loopback. Valid only for `UseSpecifiedNetworkACL` recursion option. |
| DNS_SERVER_RECURSION_DENIED_NETWORKS              | String  | A comma separated list of IP addresses or network addresses to deny recursion. Valid only for `UseSpecifiedNetworkACL` recursion option. This option is obsolete and DNS_SERVER_RECURSION_NETWORK_ACL should be used instead.  |
| DNS_SERVER_RECURSION_ALLOWED_NETWORKS             | String  | A comma separated list of IP addresses or network addresses to allow recursion. Valid only for `UseSpecifiedNetworkACL` recursion option. This option is obsolete and DNS_SERVER_RECURSION_NETWORK_ACL should be used instead. |
| DNS_SERVER_ENABLE_BLOCKING                        | Boolean | Sets the DNS server to block domain names using Blocked Zone and Block List Zone.                                                        |
| DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT              | Boolean | Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests.                    |
| DNS_SERVER_BLOCK_LIST_URLS                        | String  | A comma separated list of block list URLs.                                                                                               |
| DNS_SERVER_FORWARDERS                             | String  | A comma separated list of forwarder addresses.                                                                                           |
| DNS_SERVER_FORWARDER_PROTOCOL                     | String  | Forwarder protocol options: `Udp`, `Tcp`, `Tls`, `Https`, `HttpsJson`.                                                                   |
| DNS_SERVER_LOG_USING_LOCAL_TIME                   | Boolean | Enable this option to use local time instead of UTC for logging.                                                                         |
| DNS_SERVER_LOG_FOLDER_PATH                        | String  | The folder path on the server where the log files should be saved. The path can be relative to the DNS server's config folder.
| DNS_SERVER_LOG_MAX_LOG_FILE_DAYS                  | Integer | Max number of days to keep the log files. Log files older than the specified number of days will be deleted automatically. Set 0 to disable auto delete.
| DNS_SERVER_STATS_ENABLE_IN_MEMORY_STATS           | Boolean | This option will enable in-memory stats and only Last Hour data will be available on Dashboard. No stats data will be stored on disk.
| DNS_SERVER_STATS_MAX_STAT_FILE_DAYS               | Integer | Max number of days to keep the dashboard stats. Stat files older than the specified number of days will be deleted automatically. Set 0 to disable auto delete.
| DNS_SERVER_SSO_ENABLED                            | Boolean | Enable to allow Single Sign-On (SSO) with OpenID Connect (OIDC).
| DNS_SERVER_SSO_AUTHORITY                          | String  | The OpenID Connect (OIDC) Authority URL (Issuer).
| DNS_SERVER_SSO_CLIENT_ID                          | String  | The OpenID Connect (OIDC) Client ID.
| DNS_SERVER_SSO_CLIENT_SECRET                      | String  | The OpenID Connect (OIDC) Client Secret.
| DNS_SERVER_SSO_CLIENT_SECRET_FILE                 | String  | The path to a file that contains a plain text OpenID Connect (OIDC) Client Secret string.
| DNS_SERVER_SSO_METADATA_ADDRESS                   | String  | The OpenID Connect (OIDC) metadata discovery URL to be used instead of the default one. Configure this option only if the Single Sign-On (SSO) provider uses a different discovery URL.
| DNS_SERVER_SSO_ALLOW_SIGNUP                       | Boolean | Enable to allow automatically provisioning of user accounts for new users signing in via Single Sign-On (SSO). Keep this option disabled if you do not expect new SSO users to sign up.
| DNS_SERVER_SSO_ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS | Boolean | Enable to allow a new user to sign up via Single Sign-On (SSO) only when the user is a member of at least one Remote Group that is mapped to a Local Group in the Group Map option below. This option allows SSO administrators to restrict SSO users to control who can sign up and get access based on their group memberships.
| DNS_SERVER_SSO_GROUP_MAP                          | String  | A comma separated list of entries where each entry is a colon separated key value pair. For example, `Admins:Administrators,DNS Admins:DNS Administrators`. Map Remote Groups at Single Sign-On (SSO) provider to Local Groups for both new and existing users signed up via Single Sign-On (SSO). These SSO user's group membership will be automatically synced to mapped Local Groups each time they log in.
