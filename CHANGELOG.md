# Technitium DNS Server Change Log

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
