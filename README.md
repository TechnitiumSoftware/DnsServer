<p align="center">
	<a href="https://technitium.com/dns/">
		<img src="https://technitium.com/img/logo.png" alt="Technitium DNS Server" /><br />
		<b>Technitium DNS Server</b>
	</a><br />
	<br />
	<b>Self host a DNS server for privacy & security</b><br />
	<b>Block ads & malware at DNS level for your entire network!</b>
</p>
<p align="center">
<img src="https://technitium.com/dns/ScreenShot1.png" alt="Technitium DNS Server" />
</p>

Technitium DNS Server is an open source authoritative as well as recursive DNS server that can be used for self hosting a DNS server for privacy & security. It works out-of-the-box with no or minimal configuration and provides a user friendly web console accessible using any modern web browser.

Nobody really bothers about domain name resolution since it works automatically behind the scenes and is complex to understand. Most computer software use the operating system's DNS resolver that usually query the configured ISP's DNS server using UDP protocol. This way works well for most people but, your ISP can see and control what website you can visit even when the website employ HTTPS security. Not only that, some ISPs can redirect, block or inject content into websites you visit even when you use a different DNS provider like Google DNS or Cloudflare DNS. Having Technitium DNS Server configured to use [DNS-over-TLS](https://en.wikipedia.org/wiki/DNS_over_TLS), [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS), or [DNS-over-QUIC](https://www.ietf.org/rfc/rfc9250.html) forwarders, these privacy & security issues can be mitigated very effectively.

Be it a home network or an organization's network, having a locally running DNS server gives you more insights into your network and helps to understand it better using the DNS logs and stats. It improves overall performance since most queries are served from the DNS cache making web sites load faster by not having to wait for frequent DNS resolutions. It also gives you an additional control over your network allowing you to block domain names network wide and also allows you to route your DNS traffic securely using encrypted DNS protocols.

# Sponsored By
<p align="center">
	<a href="https://althatech.com/" target="_blank"><img src="https://technitium.com/img/logo-althatech.png" width="250" alt="Altha Technology - Censorship Resistant Data Services" title="Altha Technology - Censorship Resistant Data Services" /></a>
</p>
<p align="center">
	<a href="https://www.bartellhotels.com/" target="_blank"><img src="https://technitium.com/img/logo-bartell-hotels.png" width="300" alt="Bartell Hotels - San Diego's Unforgettable Locations" title="Bartell Hotels - San Diego's Unforgettable Locations" /></a>
	<a href="https://www.wavspeed.com/" target="_blank"><img src="https://technitium.com/img/logo-wavspeed.png" width="350" alt="Technology Investors and Integrators | WavSpeed Inc | Texas" title="Technology Investors and Integrators | WavSpeed Inc | Texas" /></a>
</p>

# Features
- Works on Windows, Linux, macOS and Raspberry Pi.
- Docker image available on [Docker Hub](https://hub.docker.com/r/technitium/dns-server).
- Installs in just a minute and works out-of-the-box with zero configuration.
- Block ads & malware using one or more block list URLs.
- Supports working as an authoritative as well as a recursive DNS server.
- Includes built-in Clustering feature to allow managing two or more DNS server instances from a single admin web console.
- High performance DNS server based on async IO that can serve millions of requests per minute even on a commodity desktop PC hardware (load tested on Intel i7-8700 CPU with more than 100,000 request/second over Gigabit Ethernet).
- Self host [DNS-over-TLS](https://www.rfc-editor.org/rfc/rfc7858.html), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html), and [DNS-over-QUIC](https://www.ietf.org/rfc/rfc9250.html) DNS services on your network.
- DNS-over-HTTPS implementation supports HTTP/1.1, HTTP/2, and HTTP/3 transport protocols.
- Supports DNS over [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) version 1 and 2 for both UDP and TCP transports.
- Use public DNS resolvers like Cloudflare, Google, Quad9, and AdGuard with [DNS-over-TLS](https://www.rfc-editor.org/rfc/rfc7858.html), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html), or [DNS-over-QUIC](https://www.ietf.org/rfc/rfc9250.html) protocols as forwarders.
- Support for latency based name server selection algorithm that works with concurrency feature for both recursive resolution and forwarders.
- Advanced caching with features like serve stale, prefetching and auto prefetching.
- Persistent caching feature that saves cache to disk when DNS server restarts.
- DNS rebinding attack protection feature available with DNS Rebinding Protection App.
- DNSSEC validation support with RSA, ECDSA & EdDSA algorithms for recursive resolver, forwarders, and conditional forwarders with NSEC and NSEC3 support.
- DNSSEC support for all supported DNS transport protocols including encrypted DNS protocols.
- DANE TLSA [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) record type support. This includes support for automatically generating the hash values using certificates in PEM format.
- SVCB & HTTPS [draft-ietf-dnsop-svcb-https](https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-12.html) record type support.
- URI [RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html) record type support.
- SSHFP [RFC 4255](https://www.rfc-editor.org/rfc/rfc4255.html) record type support.
- CNAME cloaking feature to block domain names that resolve to CNAME which are blocked.
- QNAME minimization support in recursive resolver [RFC 9156](https://www.rfc-editor.org/rfc/rfc9156.html).
- QNAME case randomization support for UDP transport protocol [draft-vixie-dnsext-dns0x20-00](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00).
- DNAME record [RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672) support.
- ANAME proprietary record support to allow using CNAME like feature at zone apex (CNAME flattening). Supports multiple ANAME records at both zone apex and sub domains.
- APP proprietary record support that allows custom DNS Apps to directly handle DNS requests and return a custom DNS response based on any business logic.
- Support for features like Split Horizon and Geolocation based responses using DNS Apps feature.
- Support for REGEX based block lists with different block lists for different client IP addresses or subnet using Advanced Blocking DNS App.
- Primary, Secondary, Stub, and Conditional Forwarder zone support.
- Static stub zone support implemented in Conditional Forwarder zone to force a domain name to resolve via given name servers using NS records.
- Supports Catalog Zones [RFC 9432](https://datatracker.ietf.org/doc/rfc9432/).
- Supports record aging where the records with expiry set are automatically removed from the zone.
- Bulk conditional forwarding support using Advanced Forwarding DNS App.
- DNSSEC signed zones support with RSA, ECDSA & EdDSA algorithms.
- DNSSEC support for both NSEC and NSEC3.
- Zone transfer with AXFR and IXFR [RFC 1995](https://www.rfc-editor.org/rfc/rfc1995.html) and DNS NOTIFY [RFC 1996](https://www.rfc-editor.org/rfc/rfc1996.html) support.
- Zone transfer over TLS (XFR-over-TLS) [RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html) support.
- Zone transfer over QUIC (XFR-over-QUIC) [RFC 9250](https://www.ietf.org/rfc/rfc9250.html) support.
- Support for zone validation using ZONEMD records [RFC 8976](https://datatracker.ietf.org/doc/rfc8976/) for Secondary zones.
- Dynamic DNS Updates [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) support with security policy.
- Secret key transaction authentication (TSIG) [RFC 8945](https://datatracker.ietf.org/doc/html/rfc8945) support for zone transfers.
- EDNS(0) [RFC6891](https://datatracker.ietf.org/doc/html/rfc6891) support.
- EDNS Client Subnet (ECS) [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871) support for recursive resolution and forwarding.
- Extended DNS Errors [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914) support.
- DNS64 function [RFC 6147](https://www.rfc-editor.org/rfc/rfc6147) support for use by IPv6 only clients using the DNS64 App.
- Support to host DNSBL / RBL block lists [RFC 5782](https://www.rfc-editor.org/rfc/rfc5782).
- Multi-user role based access with non-expiring API token support.
- Self host your domain names on your own DNS server.
- Wildcard sub domain support.
- Enable/disable zones and records to allow testing with ease.
- Built-in DNS Client with option to import responses to local zone.
- Supports out-of-order DNS request processing for DNS-over-TCP and DNS-over-TLS protocols [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766#section-7).
- Built-in DHCP Server that can work for multiple networks.
- IPv6 support in DNS server core.
- HTTP & SOCKS5 proxy support which can be configured to route DNS over [Tor Network](https://www.torproject.org/) or use [Cloudflare's hidden DNS resolver](https://blog.cloudflare.com/welcome-hidden-resolver/).
- Web console portal for easy configuration using any web browser.
- Built in HTTP API to allow 3rd party apps to control and configure the DNS server.
- Supports TOTP based Two-factor authentication (2FA).
- Built-in system logging and query logging.
- Open source cross-platform .NET 9 implementation hosted on [GitHub](https://github.com/TechnitiumSoftware/DnsServer).

# Planned Features
- Clustering support to manage two or more DNS servers.

# Installation
- **Windows**: [Download setup installer](https://download.technitium.com/dns/DnsServerSetup.zip) for easy installation.
- **Linux & Raspberry Pi**: Follow install instructions from [this blog post](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html).
- **Cross-Platform**: [Download portable app](https://download.technitium.com/dns/DnsServerPortable.tar.gz) to run on any platform that has .NET 9 installed.
- **Docker**: Pull the official image from [Docker Hub](https://hub.docker.com/r/technitium/dns-server). Use the [docker-compose.yml](https://github.com/TechnitiumSoftware/DnsServer/blob/master/docker-compose.yml) example to create a new container and edit it as required for your deployments. For more details and troubleshooting read the [install instructions](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html).

# Build Instructions
You can build the DNS server from source and install it manually by following the [Build Instructions](https://github.com/TechnitiumSoftware/DnsServer/blob/master/build.md).

# Docker Environment Variables
Technitium DNS Server supports environment variables to allow initializing the config when the DNS server starts for the first time. Read the [environment variable documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/DockerEnvironmentVariables.md) for complete details.

# API Documentation
The DNS server HTTP API allows any 3rd party app or script to configure the DNS server. The HTTP API is used by the web console and thus all the actions that the web console does can be performed via the API. Read the [HTTP API documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md) for complete details.

# Help Topics
Read the latest [online help topics](https://go.technitium.com/?id=25) which contains the DNS Server user manual and covers frequently asked questions.

# Support
For support, send an email to support@technitium.com. For any issues, feedback, or feature request, create an issue on [GitHub](https://github.com/TechnitiumSoftware/DnsServer/issues).

Join [/r/technitium](https://www.reddit.com/r/technitium/) on Reddit.

# Donate
Make contribution to Technitium and help making new software, updates, and features possible.

[Donate Now!](https://www.patreon.com/technitium)

# Blog Posts
- [Technitium Blog: How To Configure Catalog Zones For Automatic Provisioning Of Secondary Zones](https://blog.technitium.com/2024/10/how-to-configure-catalog-zones-for.html) (Oct 2024)
- [Technitium Blog: Technitium DNS Server v13 Released!](https://blog.technitium.com/2024/09/technitium-dns-server-v13-released.html) (Sept 2024)
- [Technitium Blog: Technitium DNS Server v12 Released!](https://blog.technitium.com/2024/02/technitium-dns-server-v12-released.html) (Feb 2024)
- [Technitium Blog: For DNSSEC And Why DANE Is Needed](https://blog.technitium.com/2023/05/for-dnssec-and-why-dane-is-needed.html) (May 2023)
- [Technitium Blog: How To Auto Renew SSL Certificates With Certbot Using DNS Challenge](https://blog.technitium.com/2023/03/how-to-auto-renew-ssl-certificates-with.html) (Mar 2023)
- [Technitium Blog: Configuring DNS-over-QUIC and HTTPS/3 For Technitium DNS Server](https://blog.technitium.com/2023/02/configuring-dns-over-quic-and-https3.html) (Feb 2023)
- [Technitium Blog: Technitium DNS Server v11 Released!](https://blog.technitium.com/2023/02/technitium-dns-server-v11-released.html) (Feb 2023)
- [Technitium Blog: Technitium DNS Server v10 Released!](https://blog.technitium.com/2022/11/technitium-dns-server-v10-released.html) (Nov 2022)
- [Technitium Blog: Technitium DNS Server v9 Released!](https://blog.technitium.com/2022/09/technitium-dns-server-v9-released.html) (Sept 2022)
- [Technitium Blog: How To Secure Your Domain Name With DNSSEC](https://blog.technitium.com/2022/07/how-to-secure-your-domain-name-with-.html) (Jul 2022)
- [Technitium Blog: How To Self Host Your Own Domain Name](https://blog.technitium.com/2022/06/how-to-self-host-your-own-domain-name.html) (Jun 2022)
- [Technitium Blog: Technitium DNS Server v8 Released!](https://blog.technitium.com/2022/03/technitium-dns-server-v8-released.html) (Mar 2022)
- [Technitium Blog: Running A Root Server Locally On Your DNS Resolver](https://blog.technitium.com/2021/07/running-root-server-locally-on-your-dns.html) (Jul 2021)
- [Yolan Romailler: Being ad-free on Android without rooting](https://romailler.ch/2021/04/15/misc-pihole_over_dot/) (Apr 2021)
- [Technitium Blog: Creating And Running DNS Apps On Technitium DNS Server](https://blog.technitium.com/2021/03/creating-and-running-dns-apps-on.html) (Mar 2021)
- [Technitium Blog: How To Host Your Own DNS-over-HTTPS And DNS-over-TLS Services](https://blog.technitium.com/2020/07/how-to-host-your-own-dns-over-https-and.html) (Oct 2020)
- [Technitium Blog: How To Disable Firefox DNS-over-HTTPS On Your Network](https://blog.technitium.com/2020/07/how-to-disable-firefox-dns-over-https.html) (Jul 2020)
- [Technitium Blog: How To Enforce Google Safe Search And YouTube Restricted Mode On Your Network](https://blog.technitium.com/2020/07/how-to-enforce-google-safe-search-and.html) (Jul 2020)
- [Technitium Blog: Technitium DNS Server v5 Released!](https://blog.technitium.com/2020/07/technitium-dns-server-v5-released.html) (Jul 2020)
- [Brian Wojtczak: Keep It Encrypted, Keep It Safe: Working with ESNI, DoH, and DoT](https://www.toptal.com/web/encrypted-safe-with-esni-doh-dot) (Jan 2020)
- [phra's blog: Exfiltrate Like a Pro: Using DNS over HTTPS as a C2 Channel](https://iwantmore.pizza/posts/dnscat2-over-doh.html) (Aug 2019)
- [Scott Hanselman: Exploring DNS with the .NET Core based Technitium DNS Server](https://www.hanselman.com/blog/ExploringDNSWithTheNETCoreBasedTechnitiumDNSServer.aspx) (Apr 2019)
- [Technitium Blog: Turn Raspberry Pi Into Network Wide DNS Server](https://blog.technitium.com/2019/01/turn-raspberry-pi-into-network-wide-dns.html) (Jan 2019)
- [Technitium Blog: Blocking Internet Ads Using DNS Sinkhole](https://blog.technitium.com/2018/10/blocking-internet-ads-using-dns-sinkhole.html) (Oct 2018)
- [Technitium Blog: Configuring DNS Server For Privacy & Security](https://blog.technitium.com/2018/06/configuring-dns-server-for-privacy.html) (Jun 2018)
- [Technitium Blog: Technitium DNS Server v1.3 Released!](https://blog.technitium.com/2018/06/technitium-dns-server-v13-released.html) (Jun 2018)
- [Technitium Blog: Running Technitium DNS Server on Ubuntu Linux](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html) (Nov 2017)
- [Technitium Blog: Technitium DNS Server Released!](https://blog.technitium.com/2017/11/technitium-dns-server-released.html) (Nov 2017)
