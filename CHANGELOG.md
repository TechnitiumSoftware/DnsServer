# Technitium DNS Server Change Log

## Version 6.1
Release Date: 10 April 2021

- Added DNS App Store feature that list all available apps for quick and easy installation and update.
- Added 'Overwrite' option in Add Record for zones.
- Multiple ANAME record support added.
- Added block list allowed URL feature to prevent domain names from getting added to the block list zone.
- Fixed bug in ZoneTree.
- Fixed bugs in DNS Apps.
- Split Default DNS App into 5 independent apps that are now available on the DNS App Store.
- Fixed issues in DNS Cache and updated code for memory optimization.
- Upgraded all library projects to .NET 5.
- Multiple other minor bug fixes and improvements.

## Version 6.0
Release Date: 13 March 2021

- Updated entire DNS code base to .NET 5 with new Windows installer. This upgrade will improve overall performance on Windows installations.
- Added support for DNS Application (APP) propriety record with DNS Apps feature support. DNS Apps allows creating custom apps by 3rd party using .NET that run on the DNS server allowing the apps to process DNS requests and provide custom DNS response based on any bussiness logic.
- A default DNS app (available to download separately) supports APP records capable of Split Horizon and Geolocation based responses using MaxMind's GeoIP2 City & Country databases.
- Updated dashboard charts to save legend selection state.
- Updated dashboard with Custom date selection option to display stats.
- Added option to configure max stats days in settings.
- Added option to enable/disable QNAME minimization.
- Added delete existing files option in Restore settings.
- Added support to store query stats data to allow DNS cache auto prefetch to refresh cache when DNS server restarts.
- Updated TLS certificate implementation to allow using self signed certificates for web console, DoH, and DoT.
- Added DHCP lease Reserve/Unreserve options to allow quickly reserving lease for clients.
- Updated DHCP reserved lease option to allow overriding client's host name.
- Fixed issues with DNS cache auto prefetch feature.
- Fixed multiple issues in DNS cache.
- Fixed multiple vulnerabilities causing DNS cache poisoning.
- Multiple other minor bug fixes and improvements.

## Version 5.6
Release Date: 2 January 2021

- Updated standalone console app to work on .NET 5 and removing standalone .NET Framework app support. .NET 5 update will boost performance of the DNS server on all platforms.
- Updated DNS and DHCP listener code to use async IO to improve performance.
- Added HTTPS support for web service that provides the web console access.
- Added support to change the web service local addresses.
- Updated the server to allow changing DNS server end points, the web service end points, or enabling DoH or DoT services instantly without need to manually restart the main service. Basically, you do not need to restart the DNS server app at all for applying any kind of settings as all the changes are applied dynamically.
- Added HTTP compression support in the main web service.
- Added HTTP compression for downloading block lists.
- Added option to clear and delete all dashboard stats and auto clean up old stats files from disk
- Added option to delete all log files and auto clean up old log files from disk.
- Added configurable option to disable logging, allow logging in local time, and to change log folder path.
- Added option in settings to define the refresh interval for block lists with a manual option to force refresh all block lists.
- Added support for exporting backup zip file containing selected items like config files, logs, stats, etc. and allow restoring the backup zip file without restarting the main service.
- Fixed multiple issues in DHCP server's DNS record management.
- Fixed bug in DNS server cache prefetching for stub and conditional forwarder zones causing the cached data to be overwritten by the prefetched output from recursive resolution.
- Fixed html encoding issue in web app.
- Added option in web app to list top 1000 clients, top domains and top blocked domains.
- DNS cache serve stale feature made configurable with default serve stale TTL set to 3 days instead of 7 days.
- Fixed issue in recursive resolver to avoid querying root servers when one of the parent zone's name servers exists in DNS cache.
- Breaking changes in the `getDnsSettings` and `setDnsSettings` API calls will require API clients to update the code before updating the DNS server.
- Multiple other minor bug fixes and improvements.

## Version 5.5
Release Date: 14 November 2020

- Added option to specify bootfile name for PXE booting.
- Implemented DHCP vendor specific information option.
- Implemented strict enforcing of exclusion list.
- Fixed bug in DNS initial server name that was caused due to invalid characters in the computer name.
- Added support for additional record processing for SRV records and fixed issues for NS and MX records processing.
- Multiple other minor bug fixes and improvements.

## Version 5.4
Release Date: 18 October 2020

- Implemented QNAME randomization feature [draft-vixie-dnsext-dns0x20](https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00).
- Fixed bug causing infinite loop in certain conditions when using UDP as transport.
- Fixed bug in DNS cache querying which caused the server to make unneeded queries when performing recursive resolution.
- Added Create PTR Zone option when adding A or AAAA records.
- Fixed issues with DHCP scope selection when using relay agent.
- Implemented changes to allow changing DHCP scope IP allocation from dynamic to reserved and vice versa.
- Updated DHCP scope to allow specifying Next Server Address for use with TFTP for booting.
- Multiple other minor bug fixes and improvements.

## Version 5.3
Release Date: 26 September 2020

- Fixed issues with DHCP server that caused it to not work correctly with relay agents.
- Updated DHCP server to support multiple scopes to work on a single network interface allowing it to provide different options for groups of devices.
- Multiple other minor bug fixes and improvements.

## Version 5.2
Release Date: 6 September 2020

- Added feature to allow using `certbot` to renew TLS certificates automatically when using DNS-over-HTTPS and DNS-over-TLS.
- Fixed issue in DHCP server that caused thread to block by implementing async methods.
- Fixed bug in DNS client that caused QTYPE mismatch due to QNAME minimization.
- Fixed issues in DNS-over-HTTPS client related to retries and http error handling.
- Multiple other minor bug fixes and improvements.

## Version 5.1
Release Date: 29 August 2020

- Implemented async IO to allow the DNS server handle much higher concurrent loads.
- Implemented independent thread pools for DNS web service and recursive resolver.
- Fixed bug in block list downloader that caused 0 byte file downloads.
- Fixed bug in DHCP server in creating reverse zone.
- Multiple other minor bug fixes and improvements.

## Version 5.0.2
Release Date: 18 July 2020

- Fixed issue of missing port for "This Server" in DNS Client.
- Added domain name that was blocked in the TXT record.
- Fixed bugs in CNAME cloaking implementation.
- Upgraded .NET Framework version to v4.8.
- Multiple other minor bug fixes and improvements.

## Version 5.0.1
Release Date: 6 July 2020

- Fixed serialization bug for TXT records.
- Fixed issue with reading DnsDatagram for DoH POST requests.
- Fixed bug in json serialization of DnsDatagram for DoH json format.
- Fixed bug in RTT calculation for DoH json Connection.

## Version 5.0
Release Date: 4 July 2020

- DNS Server local end points support to allow specifying alternate ports for UDP and TCP protocols.
- DNS Server performance issues caused by thread contention fixed.
- CNAME cloaking implemented to block domain names that resolve to CNAME which are blocked.
- New Block List zone implementation that uses very less memory allowing to load block lists with millions of domain names even on a Raspberry Pi with 1GB RAM.
- QNAME minimization support in recursive resolver [draft-ietf-dnsop-rfc7816bis-04](https://tools.ietf.org/html/draft-ietf-dnsop-rfc7816bis-04).
- ANAME propriety record support to allow using CNAME like feature at zone root.
- Added primary zones with NOTIFY implementation [RFC 1996](https://tools.ietf.org/html/rfc1996).
- Added secondary zones with NOTIFY implementation [RFC 1996](https://tools.ietf.org/html/rfc1996).
- Added stub zones with feature to override records.
- Added conditional forwarder zones with all protocols including DNS-over-HTTPS and DNS-over-TLS support.
- Conditional forwarder zones with feature to override records.
- Conditional forwarder zones with support for multiple forwarders with different sub domain names.
- ByteTree based zone tree implementation which is a complete lock-less and thread safe tree allowing concurrent read and write operations.
- Fixed bug in parsing large TXT records.
- DNS Client with internal support for concurrent querying. This allows querying multiple forwarders simultaneously to return fastest response of all.
- DNS Client with support to import records via zone transfer.
- Multiple other bug fixes in DNS and DHCP modules.
