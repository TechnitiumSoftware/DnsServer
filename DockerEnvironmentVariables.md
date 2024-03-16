# Technitium DNS Server Docker Environment Variables

Technitium DNS Server supports environment variables to allow initializing the config when the DNS server starts for the first time. These environment variables are useful for creating docker container and can be used as shown in the [docker-compose.yml](https://github.com/TechnitiumSoftware/DnsServer/blob/master/docker-compose.yml) file.

NOTE! These environment variables are read by the DNS server only when the DNS config file does not exists i.e. when the DNS server starts for the first time.

The environment variables are described below:

| Environment Variable                       | Type    | Description                                                                                                                              |
| ------------------------------------------ | ------- | -----------------------------------------------------------------------------------------------------------------------------------------|
| DNS_SERVER_DOMAIN                          | String  | The primary domain name used by this DNS Server to identify itself.                                                                      |
| DNS_SERVER_ADMIN_PASSWORD                  | String  | The DNS web console admin user password.                                                                                                 |
| DNS_SERVER_ADMIN_PASSWORD_FILE             | String  | The path to a file that contains a plain text password for the DNS web console admin user.                                               |
| DNS_SERVER_PREFER_IPV6                     | Boolean | DNS Server will use IPv6 for querying whenever possible with this option enabled.                                                        |
| DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES     | String  | A comma separated list of IP addresses for the DNS web console to listen on.                                                             |
| DNS_SERVER_WEB_SERVICE_HTTP_PORT           | Integer | The TCP port number for the DNS web console over HTTP protocol.                                                                          |
| DNS_SERVER_WEB_SERVICE_HTTPS_PORT          | Integer | The TCP port number for the DNS web console over HTTPS protocol.                                                                         |
| DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS        | Boolean | Enables HTTPS for the DNS web console.                                                                                                   |
| DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT| Boolean | Enables self signed TLS certificate for the DNS web console.                                                                             |
| DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP | Boolean | Enables DNS server optional protocol DNS-over-HTTP on TCP port 80 to be used with a TLS terminating reverse proxy like nginx.            |
| DNS_SERVER_RECURSION                       | String  | Recursion options: `Allow`, `Deny`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworks`.                                               |
| DNS_SERVER_RECURSION_DENIED_NETWORKS       | String  | A comma separated list of IP addresses or network addresses to deny recursion. Valid only for `UseSpecifiedNetworks` recursion option.   |
| DNS_SERVER_RECURSION_ALLOWED_NETWORKS      | String  | A comma separated list of IP addresses or network addresses to allow recursion. Valid only for `UseSpecifiedNetworks` recursion option.  |
| DNS_SERVER_ENABLE_BLOCKING                 | Boolean | Sets the DNS server to block domain names using Blocked Zone and Block List Zone.                                                        |
| DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT       | Boolean | Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests.                    |
| DNS_SERVER_BLOCK_LIST_URLS                 | String  | A comma separated list of block list URLs.                                                                                               |
| DNS_SERVER_FORWARDERS                      | String  | A comma separated list of forwarder addresses.                                                                                           |
| DNS_SERVER_FORWARDER_PROTOCOL              | String  | Forwarder protocol options: `Udp`, `Tcp`, `Tls`, `Https`, `HttpsJson`.                                                                   |
| DNS_SERVER_LOG_USING_LOCAL_TIME            | Boolean | Enable this option to use local time instead of UTC for logging.                                                                         |
