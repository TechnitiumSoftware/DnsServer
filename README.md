<p align="center">
	<a href="https://technitium.com/dns/">
		<img src="https://technitium.com/img/logo.png" alt="Technitium DNS Server" /><br />
		<h2>Technitium DNS Server</h2>
	</a>
	<h3>Get a personal local DNS Server for privacy & security</h3>
</p>
<br />
<img src="https://technitium.com/dns/ScreenShot1.png" alt="Technitium DNS Server" />
<br />

Technitium DNS Server is an open source tool that can be used for self hosting a local DNS server for privacy & security or, used for experimentation/testing by software developers on their computer. It works out-of-the-box with no or minimal configuration and provides a user friendly web console accessible using any web browser.

Nobody really bothers about domain name resolution since it works automatically behind the scenes and is complex to understand. Most computer software use the operating system's DNS resolver that usually query the configured ISP's DNS server using UDP protocol. This way works well for most people but, your ISP can see and control what website you can visit even when the website employ HTTPS security. Not only that, some ISPs can redirect, block or inject content into websites you visit even when you use a different DNS provider like Google DNS or Cloudflare DNS. Having Technitium DNS Server configured to use DNS-over-TLS or DNS-over-HTTPS forwarders, these privacy & security issues can be mitigated very effectively.

Developers regularly use the hosts file for configuring an IP address for a domain under testing. However, using the hosts file is cumbersome at times and can only be used to resolve domain name to an IP address. With a fully configurable DNS server running on your local machine, you can configure not just simple A records (for IP address) but, also configure other types of records like CNAME or MX etc. This allow you to have more control and power when you want to do testing that simulates the exact configuration that you have running on production.

Applications of using a locally hosted DNS server is limited only by the user's imagination!

# Features
- Works on Windows, Linux, macOS and Raspberry Pi.
- Installs in just a minute and works out-of-the-box with zero configuration.
- Block Ads using one or more block list URLs.
- Run DNS-over-TLS and DNS-over-HTTPS DNS service on your network.
- Use public DNS resolvers like Cloudflare, Google & Quad9 with DNS-over-TLS and DNS-over-HTTPS protocols as forwarders.
- Advance caching with features like serve stale, prefetching and auto prefetching.
- Supports working as an authoritative as well as a recursive DNS server.
- Host domain names on your own server.
- Wildcard sub domain support.
- Enable/disable zones and records to allow testing with ease.
- Built-in DNS Client with option to import responses to local zone.
- Supports out-of-order DNS request processing for DNS-over-TCP and DNS-over-TLS protocols.
- IPv6 support in DNS server core.
- HTTP & SOCKS5 proxy support which can be used with Tor network.
- Web console portal for easy configuration using any web browser.
- Built-in system logging and query logging.
- Open source cross-platform .NET Core implementation hosted on GitHub.

# Installation
- **Windows**: [Download setup installer](https://technitium.com/dns/) for easy installation.
- **Linux, macOS & Raspberry**: Follow installation setup from [this blog post](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html).

# Help Topics
Read the latest [online help topics](https://go.technitium.com/?id=25) which contains the DNS Server user manual and covers frequently asked questions.

# Support
For support, send an email to support@technitium.com. For any issues, feedback, or feature request, create an issue on [GitHub](https://github.com/TechnitiumSoftware/DnsServer/issues).

# Become A Patron
Make contribution to Technitium by becoming a Patron and help making new software, updates, and features possible.

[Become a Patron now!](https://www.patreon.com/technitium)

# Blog Posts
- [Technitium Blog: Turn Raspberry Pi Into Network Wide DNS Server](https://blog.technitium.com/2019/01/turn-raspberry-pi-into-network-wide-dns.html)
- [Technitium Blog: Blocking Internet Ads Using DNS Sinkhole](https://blog.technitium.com/2018/10/blocking-internet-ads-using-dns-sinkhole.html)
- [Technitium Blog: Configuring DNS Server For Privacy & Security](https://blog.technitium.com/2018/06/configuring-dns-server-for-privacy.html)
- [Scott Hanselman: Exploring DNS with the .NET Core based Technitium DNS Server](https://www.hanselman.com/blog/ExploringDNSWithTheNETCoreBasedTechnitiumDNSServer.aspx)
